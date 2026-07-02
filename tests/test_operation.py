'''
This file is part of rop3 (https://github.com/reverseame/rop3).

rop3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

rop3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with rop3. If not, see <https://www.gnu.org/licenses/>.
'''

import rop3.operation as operation

from conftest import make_gadget


def test_lc_matches_pop_reg(x64):
    ''' lc (load constant) matches `pop <reg> ; ret`. '''
    gadgets = [
        make_gadget(b'\x58\xc3', 0x1000),   # pop rax ; ret
        make_gadget(b'\x5b\xc3', 0x1010),   # pop rbx ; ret
        make_gadget(b'\x90\xc3', 0x1020),   # nop ; ret  (no match)
    ]
    matched = operation.Operation('lc').filter_gadgets(gadgets)
    texts = {g.text_repr for g in matched}
    assert 'pop rax ; ret' in texts
    assert 'pop rbx ; ret' in texts
    assert 'nop ; ret' not in texts


def test_lc_with_dst_filter(x64):
    gadgets = [
        make_gadget(b'\x58\xc3', 0x1000),   # pop rax ; ret
        make_gadget(b'\x5b\xc3', 0x1010),   # pop rbx ; ret
    ]
    matched = operation.Operation('lc', dst='rax').filter_gadgets(gadgets)
    assert [g.text_repr for g in matched] == ['pop rax ; ret']
    assert matched[0].dst == 'rax'


def test_filter_gadgets_empty_input(x64):
    assert operation.Operation('lc').filter_gadgets([]) == []


def test_filter_gadgets_does_not_mutate_input(x64):
    ''' filter_gadgets must annotate copies, not the shared input gadgets. '''
    g = make_gadget(b'\x58\xc3', 0x1000)             # pop rax ; ret
    assert g.op is None and g.dst is None
    matched = operation.Operation('lc', dst='rax').filter_gadgets([g])
    assert matched and matched[0] is not g           # a copy was returned
    assert matched[0].op == 'lc' and matched[0].dst == 'rax'
    # original is untouched
    assert g.op is None and g.dst is None and g.side_regs == set()


def test_operand_parse_imm_supports_hex_and_negative(x64):
    ''' Regression: immediates parsed with int(x, 0). '''
    op = operation.Operand('rax')
    assert op._parse_imm('0xffffffff') == 0xffffffff
    assert op._parse_imm('-1') == -1
    assert op._parse_imm(42) == 42


def test_ld_with_src_matches_memory_not_register(x64):
    '''
    Regression (#30, #33): `ld` (mov dst, [src]) with a concrete --src must
    match a memory load `mov <reg>, [src]`, not a register move `mov <reg>, src`.
    A previous bug overwrote the memory operand type with op_reg in set_src.
    '''
    gadgets = [
        make_gadget(b'\x48\x8b\x03\xc3', 0x1000),   # mov rax, [rbx] ; ret
        make_gadget(b'\x48\x89\xd8\xc3', 0x1010),   # mov rax, rbx ; ret (must NOT match)
    ]
    matched = operation.Operation('ld', src='rbx').filter_gadgets(gadgets)
    assert [g.text_repr for g in matched] == ['mov rax, qword ptr [rbx] ; ret']


def test_ld_does_not_match_immediate_load(x64):
    '''
    Regression (#33, error 3): a generic memory address must not be resolved
    into an immediate, so `mov rax, 0xcafe` is not a valid `ld` (load).
    '''
    gadgets = [
        make_gadget(b'\x48\xc7\xc0\xfe\xca\x00\x00\xc3', 0x1000),   # mov rax, 0xcafe ; ret
    ]
    assert operation.Operation('ld').filter_gadgets(gadgets) == []


def test_set_dst_preserves_memory_type(x64):
    '''
    Regression (#33, error 1): binding a concrete register to a `[dst]`
    placeholder must keep the operand a memory operand, not turn it into a reg.
    '''
    op = operation.Operand('[dst]')
    assert op.is_mem()
    op.set_dst('rax')
    assert op.is_mem()
    assert op.reg == 'rax'


def test_set_src_preserves_memory_type(x64):
    ''' Regression (#33, error 1): same as above for the `[src]` placeholder. '''
    op = operation.Operand('[src]')
    assert op.is_mem()
    op.set_src('rbx')
    assert op.is_mem()
    assert op.reg == 'rbx'


def test_set_dst_accepts_immediate(x64):
    '''
    Regression (#33, error 2): set_dst must accept immediates like set_src,
    producing an op_imm operand rather than rejecting the value.
    '''
    op = operation.Operand('dst')
    op.set_dst('0x10')
    assert op.is_imm()
    assert op.imm == 0x10


def test_xchg_src_counted_as_side_effect(x64):
    '''
    Regression (#31): in `xchg dst, src` the `src` register is clobbered, so it
    must be reported as a side effect (it was wrongly excluded before).
    '''
    gadget = make_gadget(b'\x48\x93\xc3', 0x1000)   # xchg rbx, rax ; ret
    matched = operation.Operation('mov', dst='rbx', src='rax').filter_gadgets([gadget])
    assert len(matched) == 1
    assert 'rax' in matched[0].side_regs


def test_mov_matches_clc_cmovae(x64):
    '''
    Regression (#32): the mov ROPLang uses the valid Capstone mnemonics
    `cmovae`/`cmovb` (not `cmovc`), so `clc ; cmovae dst, src` is a valid mov.
    '''
    gadget = make_gadget(b'\xf8\x48\x0f\x43\xc3\xc3', 0x1000)   # clc ; cmovae rax, rbx ; ret
    matched = operation.Operation('mov', dst='rax', src='rbx').filter_gadgets([gadget])
    assert [g.text_repr for g in matched] == ['clc ; cmovae rax, rbx ; ret']
