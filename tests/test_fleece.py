"""Known-answer tests for decode_fleece.

The first two documents are the byte tables printed in couchbase/fleece Fleece.md at
8ce5f690480b77c0f93d03f456a29828b5a55d66, typed in here, so they do not depend on the
writer in builders.py. The rest are built with that writer to exercise each tag.
"""
import math
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cblite_parser import UNDEFINED, FleeceError, decode_fleece  # noqa: E402
from builders import DELETE, fleece, fleece_inherited  # noqa: E402


class SpecDocuments(unittest.TestCase):
    def test_narrow_dict_from_fleece_md(self):
        self.assertEqual(decode_fleece(bytes.fromhex('43666f6f70018003007b8003')), {'foo': 123})

    def test_wide_dict_from_fleece_md(self):
        self.assertEqual(decode_fleece(bytes.fromhex('780143666f6f007b00008005')), {'foo': 123})


class Scalars(unittest.TestCase):
    def test_small_ints_are_twelve_bit_signed(self):
        for value in (0, 1, 2047, -1, -2048, 123):
            self.assertEqual(decode_fleece(fleece(value)), value)

    def test_long_ints_signed_and_unsigned(self):
        for value in (2048, -2049, 1 << 31, -(1 << 40), (1 << 63) - 1, -(1 << 63)):
            self.assertEqual(decode_fleece(fleece([value]))[0], value)
        self.assertEqual(decode_fleece(fleece([(1 << 64) - 1]))[0], (1 << 64) - 1)

    def test_doubles(self):
        for value in (0.5, -1792603629.427, 1e300):
            self.assertEqual(decode_fleece(fleece([value]))[0], value)

    def test_float32_reads_at_offset_two(self):
        f32 = b'\x20\x00' + struct.pack('<f', 1.5)
        doc = f32 + b'\x60\x01' + struct.pack('>H', 0x8000 | 4)
        doc += struct.pack('>H', 0x8000 | 2)
        self.assertEqual(decode_fleece(doc), [1.5])

    def test_specials(self):
        self.assertEqual(decode_fleece(fleece([None, True, False])), [None, True, False])
        self.assertIs(decode_fleece(b'\x3c\x00'), UNDEFINED)

    def test_strings_short_long_and_unicode(self):
        for text in ('', 'a', 'fourteen chars', 'exactly fifteen', 'x' * 300, 'café ☕'):
            self.assertEqual(decode_fleece(fleece([text]))[0], text)

    def test_binary(self):
        self.assertEqual(decode_fleece(fleece([b'\x00\xffdata' * 10]))[0], b'\x00\xffdata' * 10)


class Collections(unittest.TestCase):
    def test_nested(self):
        value = {'a': [1, 'two', {'b': None}], 'c': {'d': [[], {}]}}
        self.assertEqual(decode_fleece(fleece(value)), value)

    def test_long_count_is_2047_plus_varint(self):
        # Array.cc: a count of 0x7FF means 2047 plus a varint that follows the header
        value = list(range(2050))
        doc = fleece([v % 2000 for v in value])
        self.assertEqual(doc[:2], b'\x67\xff')
        self.assertEqual(decode_fleece(doc), [v % 2000 for v in value])

    def test_wide_collection(self):
        value = {'k': 'a value long enough to live out of line', 'n': 5}
        self.assertEqual(decode_fleece(fleece(value, wide=True)), value)

    def test_root_behind_narrow_then_wide_pointer(self):
        # Fleece.md "Finding the root": the trailing narrow pointer may lead to a wide one
        doc = b'\x43abc' + struct.pack('>I', 0x80000000 | 2)
        doc += struct.pack('>H', 0x8000 | 2)
        self.assertEqual(decode_fleece(doc), 'abc')

    def test_shared_keys_map_integer_keys(self):
        keys = ['ownerId', 'modelType']
        doc = fleece({'modelType': 'file', 'ownerId': 'x1', 'plain': 1}, shared_keys=keys)
        self.assertEqual(decode_fleece(doc), {0: 'x1', 1: 'file', 'plain': 1})
        self.assertEqual(decode_fleece(doc, keys), {'ownerId': 'x1', 'modelType': 'file', 'plain': 1})

    def test_out_of_range_shared_key_stays_an_int(self):
        doc = fleece({5: 'v'})
        self.assertEqual(decode_fleece(doc, ['only']), {5: 'v'})

    def test_dict_inheritance_and_deletion(self):
        doc = fleece_inherited({'a': 1, 'b': 2, 'c': 3}, {'b': 20, 'c': DELETE})
        self.assertEqual(decode_fleece(doc), {'a': 1, 'b': 20})


class Refusals(unittest.TestCase):
    def test_odd_and_empty_lengths(self):
        for data in (b'', b'\x00', b'\x00\x00\x00'):
            with self.assertRaises(FleeceError):
                decode_fleece(data)

    def test_extern_pointer_is_refused_not_followed(self):
        doc = b'\x41x' + b'\x60\x01' + struct.pack('>H', 0xC000 | 2)
        doc += struct.pack('>H', 0x8000 | 2)
        with self.assertRaises(FleeceError):
            decode_fleece(doc)

    def test_legacy_narrow_pointer_past_32k_resolves(self):
        # a pointer from before the extern flag existed, reaching more than 32 KiB back, so its
        # offset sets the bit that now means extern (Pointer.cc derefExtern)
        filler = 33000
        doc = bytearray(b'\x43abc')                       # "abc" at 0
        doc += b'\x5f' + bytes([filler & 0x7F | 0x80, (filler >> 7) & 0x7F | 0x80, filler >> 14]) + b'\x00' * filler
        if len(doc) % 2:
            doc += b'\x00'
        array_at = len(doc)
        doc += b'\x60\x01'
        units = len(doc) // 2                              # back to offset 0
        self.assertTrue(units & 0x4000)
        doc += struct.pack('>H', 0x8000 | units)
        doc += struct.pack('>H', 0x8000 | ((len(doc) - array_at) // 2))
        self.assertEqual(decode_fleece(bytes(doc)), ['abc'])

    def test_wide_extern_pointer_is_refused(self):
        doc = b'\x41x' + b'\x68\x01' + struct.pack('>I', 0xC0000000 | 2)
        doc += struct.pack('>H', 0x8000 | 3)
        with self.assertRaises(FleeceError):
            decode_fleece(doc)

    def test_pointer_before_the_start_is_refused(self):
        with self.assertRaises(FleeceError):
            decode_fleece(struct.pack('>H', 0x8000 | 5))

    def test_truncated_string(self):
        # a string at 0 whose varint length (16) runs past the end, held by a one-item array
        doc = b'\x4f\x10ab' + b'\x60\x01' + struct.pack('>H', 0x8000 | 3) + struct.pack('>H', 0x8000 | 2)
        with self.assertRaisesRegex(FleeceError, 'string runs past'):
            decode_fleece(doc)

    def test_nan_round_trip_is_a_float(self):
        value = decode_fleece(fleece([float('nan')]))[0]
        self.assertTrue(math.isnan(value))


if __name__ == '__main__':
    unittest.main()
