import json

from sentry_relay._compat import string_types, iteritems, text_type
from sentry_relay._lowlevel import lib, ffi
from sentry_relay.utils import (
    encode_str,
    decode_str,
    rustcall,
    RustObject,
    attached_refs,
    make_buf,
)


__all__ = [
    "split_chunks",
    "meta_with_chunks",
    "StoreNormalizer",
    "GeoIpLookup",
    "scrub_event",
    "is_glob_match",
    "VALID_PLATFORMS",
]


VALID_PLATFORMS = frozenset()


def _init_valid_platforms():
    global VALID_PLATFORMS

    size_out = ffi.new("uintptr_t *")
    strings = rustcall(lib.relay_valid_platforms, size_out)

    valid_platforms = []
    for i in range(int(size_out[0])):
        valid_platforms.append(decode_str(strings[i]))

    VALID_PLATFORMS = frozenset(valid_platforms)


_init_valid_platforms()


def split_chunks(string, remarks):
    return json.loads(
        decode_str(
            rustcall(
                lib.relay_split_chunks,
                encode_str(string),
                encode_str(json.dumps(remarks)),
            )
        )
    )


def meta_with_chunks(data, meta):
    if not isinstance(meta, dict):
        return meta

    result = {}
    for key, item in iteritems(meta):
        if key == "" and isinstance(item, dict):
            result[""] = item.copy()
            if item.get("rem") and isinstance(data, string_types):
                result[""]["chunks"] = split_chunks(data, item["rem"])
        elif isinstance(data, dict):
            result[key] = meta_with_chunks(data.get(key), item)
        elif isinstance(data, list):
            int_key = int(key)
            val = data[int_key] if int_key < len(data) else None
            result[key] = meta_with_chunks(val, item)
        else:
            result[key] = item

    return result


class GeoIpLookup(RustObject):
    __dealloc_func__ = lib.relay_geoip_lookup_free
    __slots__ = ("_path",)

    @classmethod
    def from_path(cls, path):
        if isinstance(path, text_type):
            path = path.encode("utf-8")
        rv = cls._from_objptr(rustcall(lib.relay_geoip_lookup_new, path))
        rv._path = path
        return rv

    def __repr__(self):
        return "<GeoIpLookup %r>" % (self._path,)


class StoreNormalizer(RustObject):
    __dealloc_func__ = lib.relay_store_normalizer_free
    __init__ = object.__init__
    __slots__ = ("__weakref__",)

    def __new__(cls, geoip_lookup=None, **config):
        config = json.dumps(config)
        geoptr = geoip_lookup._get_objptr() if geoip_lookup is not None else ffi.NULL
        rv = cls._from_objptr(
            rustcall(lib.relay_store_normalizer_new, encode_str(config), geoptr)
        )
        if geoip_lookup is not None:
            attached_refs[rv] = geoip_lookup
        return rv

    def normalize_event(self, event=None, raw_event=None):
        if raw_event is None:
            raw_event = _serialize_event(event)

        event = _encode_raw_event(raw_event)
        rv = self._methodcall(lib.relay_store_normalizer_normalize_event, event)
        return json.loads(decode_str(rv))


def _serialize_event(event):
    raw_event = json.dumps(event, ensure_ascii=False)
    if isinstance(raw_event, text_type):
        raw_event = raw_event.encode("utf-8", errors="replace")
    return raw_event


def _encode_raw_event(raw_event):
    event = encode_str(raw_event, mutable=True)
    rustcall(lib.relay_translate_legacy_python_json, event)
    return event


def scrub_event(config, data):
    if not config:
        return data

    config = json.dumps(config)

    raw_event = _serialize_event(data)
    event = _encode_raw_event(raw_event)

    rv = rustcall(lib.relay_scrub_event, encode_str(config), event)
    return json.loads(decode_str(rv))


def is_glob_match(
    value,
    pat,
    double_star=False,
    case_insensitive=False,
    path_normalize=False,
    allow_newline=False,
):
    flags = 0
    if double_star:
        flags |= lib.GLOB_FLAGS_DOUBLE_STAR
    if case_insensitive:
        flags |= lib.GLOB_FLAGS_CASE_INSENSITIVE
        # Since on the C side we're only working with bytes we need to lowercase the pattern
        # and value here.  This works with both bytes and unicode strings.
        value = value.lower()
        pat = pat.lower()
    if path_normalize:
        flags |= lib.GLOB_FLAGS_PATH_NORMALIZE
    if allow_newline:
        flags |= lib.GLOB_FLAGS_ALLOW_NEWLINE

    if isinstance(value, text_type):
        value = value.encode("utf-8")
    return rustcall(lib.relay_is_glob_match, make_buf(value), encode_str(pat), flags)