"""Resolve ColdFire signatures only at instruction-aligned addresses."""

import unittest

from emu.symbols import H, InstructionOpcode


class InstructionOpcodeTests(unittest.TestCase):
    def setUp(self):
        self.opcode = bytes.fromhex('12da12da53826600')
        self.rule = InstructionOpcode(H.of(self.opcode))

    def test_ignores_odd_address_match(self):
        image = self.opcode + b'X' + self.opcode
        self.assertEqual(self.rule.resolve(image, 0x40000400, {})[0], 0x40000400)

    def test_rejects_no_aligned_match(self):
        self.assertIsNone(self.rule.resolve(b'X' + self.opcode, 0x40000400, {})[0])

    def test_rejects_multiple_aligned_matches(self):
        image = self.opcode + b'XX' + self.opcode
        self.assertIsNone(self.rule.resolve(image, 0x40000400, {})[0])

    def test_alignment_uses_absolute_address(self):
        self.assertEqual(
            self.rule.resolve(b'X' + self.opcode, 0x40000401, {})[0], 0x40000402
        )
