import json
import msgpack
import uuid

import pytest
import os
import confluent_kafka as kafka
from copy import deepcopy


@pytest.fixture
def get_topic_name():
    """
    Generate a unique topic name for each test
    """
    random = uuid.uuid4().hex
    return lambda topic: f"relay-test-{topic}-{random}"


@pytest.fixture
def processing_config(get_topic_name):
    """
    Returns a minimal configuration for setting up a relay capable of processing
    :param options: initial options to be merged
    :return: the altered options
    """

    def inner(options=None):
        # The Travis script sets the kafka bootstrap server into system environment variable.
        bootstrap_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVER", "127.0.0.1:9092")

        options = deepcopy(options)  # avoid lateral effects

        if options is None:
            options = {}
        if options.get("processing") is None:
            options["processing"] = {}
        processing = options["processing"]
        processing["enabled"] = True
        if processing.get("kafka_config") is None:
            processing["kafka_config"] = [
                {"name": "bootstrap.servers", "value": bootstrap_servers},
                # {'name': 'batch.size', 'value': '0'}  # do not batch messages
            ]
        if processing.get("topics") is None:
            processing["topics"] = {
                "events": get_topic_name("events"),
                "attachments": get_topic_name("attachments"),
                "transactions": get_topic_name("transactions"),
                "outcomes": get_topic_name("outcomes"),
                "sessions": get_topic_name("sessions"),
            }

        if not processing.get("redis"):
            processing["redis"] = "redis://127.0.0.1"

        processing[
            "projectconfig_cache_prefix"
        ] = f"relay-test-relayconfig-{uuid.uuid4()}"

        return options

    return inner


def _sync_wait_on_result(futures_dict):
    """
    Synchronously waits on all futures returned by the admin_client api.
    :param futures_dict: the api returns a dict of futures that can be awaited
    """
    # just wait on all futures returned by the async operations of the admin_client
    for f in futures_dict.values():
        f.result(5)  # wait up to 5 seconds for the admin operation to finish


@pytest.fixture
def relay_with_processing(relay, mini_sentry, processing_config, get_topic_name):
    """
    Creates a fixture that configures a relay with processing enabled and that forwards
    requests to the test ingestion topics
    """

    def inner(options=None):
        options = processing_config(options)

        kafka_config = {}
        for elm in options["processing"]["kafka_config"]:
            kafka_config[elm["name"]] = elm["value"]

        return relay(mini_sentry, options=options)

    return inner


@pytest.fixture
def kafka_consumer(request, get_topic_name, processing_config):
    """
    Creates a fixture that, when called, returns an already subscribed kafka consumer.
    """

    def inner(topic: str, options=None):
        topics = [get_topic_name(topic)]
        options = processing_config(options)
        # look for the servers (it is the only config we are interested in)
        servers = [
            elm["value"]
            for elm in options["processing"]["kafka_config"]
            if elm["name"] == "bootstrap.servers"
        ]
        if len(servers) < 1:
            raise ValueError(
                "Bad kafka_config, could not find 'bootstrap.servers'.\n"
                "The configuration should have an entry of the format \n"
                "{name:'bootstrap.servers', value:'127.0.0.1'} at path 'processing.kafka_config'"
            )

        servers = servers[0]

        settings = {
            "bootstrap.servers": servers,
            "group.id": "test-consumer-%s" % uuid.uuid4().hex,
            "enable.auto.commit": True,
            "auto.offset.reset": "earliest",
        }

        consumer = kafka.Consumer(settings)
        consumer.assign([kafka.TopicPartition(t, 0) for t in topics])

        def die():
            consumer.close()

        request.addfinalizer(die)
        return consumer

    return inner


class ConsumerBase(object):
    # First poll takes forever, the next ones are fast
    def poll(self):
        rv = self.consumer.poll(timeout=5)
        return rv


@pytest.fixture
def outcomes_consumer(kafka_consumer):
    return lambda: OutcomesConsumer(kafka_consumer("outcomes"))


class OutcomesConsumer(ConsumerBase):
    def __init__(self, consumer):
        self.consumer = consumer

    def get_outcome(self):
        outcome = self.poll()
        assert outcome is not None
        assert outcome.error() is None
        return json.loads(outcome.value())

    def assert_rate_limited(self, reason, key_id=None):
        outcome = self.get_outcome()
        assert outcome["outcome"] == 2, outcome
        assert outcome["reason"] == reason
        if key_id is not None:
            assert outcome["key_id"] == key_id

    def assert_dropped_internal(self):
        outcome = self.get_outcome()
        assert outcome["outcome"] == 3
        assert outcome["reason"] == "internal"

    def assert_dropped_unknown_project(self):
        outcome = self.get_outcome()
        assert outcome["outcome"] == 3
        assert outcome["reason"] == "project_id"


@pytest.fixture
def events_consumer(kafka_consumer):
    return lambda: EventsConsumer(kafka_consumer("events"))


@pytest.fixture
def transactions_consumer(kafka_consumer):
    return lambda: EventsConsumer(kafka_consumer("transactions"))


@pytest.fixture
def attachments_consumer(kafka_consumer):
    return lambda: AttachmentsConsumer(kafka_consumer("attachments"))


@pytest.fixture
def sessions_consumer(kafka_consumer):
    return lambda: SessionsConsumer(kafka_consumer("sessions"))


class SessionsConsumer(ConsumerBase):
    def __init__(self, consumer):
        self.consumer = consumer

    def get_session(self):
        message = self.poll()
        assert message is not None
        assert message.error() is None

        return json.loads(message.value())


class EventsConsumer(ConsumerBase):
    def __init__(self, consumer):
        self.consumer = consumer

    def get_event(self):
        message = self.poll()
        assert message is not None
        assert message.error() is None

        event = msgpack.unpackb(message.value(), raw=False, use_list=False)
        assert event["type"] == "event"
        return json.loads(event["payload"].decode("utf8")), event

    def get_message(self):
        message = self.poll()
        assert message is not None
        assert message.error() is None

        return message, msgpack.unpackb(message.value(), raw=False, use_list=False)

    def try_get_event(self):
        message = self.poll()
        if message is None:
            return None, None
        assert message.error() is None

        event = msgpack.unpackb(message.value(), raw=False, use_list=False)
        assert event["type"] == "event"
        return json.loads(event["payload"].decode("utf8")), event


class AttachmentsConsumer(EventsConsumer):
    def get_attachment_chunk(self):
        message = self.poll()
        assert message is not None
        assert message.error() is None

        v = msgpack.unpackb(message.value(), raw=False, use_list=False)
        assert v["type"] == "attachment_chunk", v["type"]
        return v["payload"], v

    def get_individual_attachment(self):
        message = self.poll()
        assert message is not None
        assert message.error() is None

        v = msgpack.unpackb(message.value(), raw=False, use_list=False)
        assert v["type"] == "attachment", v["type"]
        return v
