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

import pytest

import rop3.ropchain as ropchain_mod
from rop3.ropchain import RopChain

from conftest import make_gadget


def _op(op, dst=None, src=None):
    return {'data': f'{op}({dst or ""},{src or ""})', 'op': op, 'dst': dst, 'src': src}


def test_search_simple_concrete_chain(x64):
    gadgets = [
        make_gadget(b'\x58\xc3', 0x1000),   # pop rax ; ret
        make_gadget(b'\x5b\xc3', 0x1010),   # pop rbx ; ret
    ]
    results = list(RopChain(None).search(gadgets, [_op('lc', dst='rax')]))
    assert results
    assert len(results[0]) == 1
    assert results[0][0].text_repr == 'pop rax ; ret'


def test_search_two_step_chain(x64):
    gadgets = [
        make_gadget(b'\x58\xc3', 0x1000),   # pop rax ; ret
        make_gadget(b'\x5b\xc3', 0x1010),   # pop rbx ; ret
    ]
    chain = [_op('lc', dst='rax'), _op('lc', dst='rbx')]
    results = list(RopChain(None).search(gadgets, chain))
    assert results
    texts = [g.text_repr for g in results[0]]
    assert texts == ['pop rax ; ret', 'pop rbx ; ret']


def test_search_raises_when_no_gadget(x64):
    gadgets = [make_gadget(b'\x90\xc3', 0x1000)]   # nop ; ret (no lc)
    with pytest.raises(ropchain_mod.RopChainNotFound):
        list(RopChain(None).search(gadgets, [_op('lc', dst='rax')]))


def test_search_generic_registers(x64):
    gadgets = [
        make_gadget(b'\x48\x89\xd8\xc3', 0x1000),   # mov rax, rbx ; ret
        make_gadget(b'\x48\x89\xd1\xc3', 0x1010),   # mov rcx, rdx ; ret
    ]
    chain = [_op('mov', dst='REG1', src='REG2')]
    results = list(RopChain(None).search(gadgets, chain))
    assert results
    assert all(len(r) == 1 for r in results)


def test_explicit_dst_clears_clobbered_register(x64):
    '''
    Regression (#34): a register written by a later step must no longer be
    considered clobbered by an earlier step.

    Step 1 `lc(rax)` uses `pop rax ; pop rbx ; ret`, which clobbers rbx.
    Step 2 `lc(rbx)` rewrites rbx, so it must be clean again for step 3
    `mov(rdx, rbx)`, which reads rbx. Before the fix the stale clobber on rbx
    blocked step 3 and no chain was found.
    '''
    gadgets = [
        make_gadget(b'\x58\x5b\xc3', 0x1000),       # pop rax ; pop rbx ; ret
        make_gadget(b'\x5b\xc3', 0x1010),           # pop rbx ; ret
        make_gadget(b'\x48\x89\xda\xc3', 0x1020),   # mov rdx, rbx ; ret
    ]
    chain = [
        _op('lc', dst='rax'),
        _op('lc', dst='rbx'),
        _op('mov', dst='rdx', src='rbx'),
    ]
    results = list(RopChain(None).search(gadgets, chain))
    assert results
    assert [g.text_repr for g in results[0]] == [
        'pop rax ; pop rbx ; ret',
        'pop rbx ; ret',
        'mov rdx, rbx ; ret',
    ]


def test_parse_negative_constant_source(x64, tmp_path):
    '''
    Regression (#38): a minus sign before a constant (e.g. -1) must be parsed
    as the source operand. Before the fix REGEX_OP did not allow '-' in an
    operand and the line failed with "Unable to parse operation".
    '''
    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('sub(rax, -1)\n')
    parsed = RopChain(None)._parse_ropfile(str(ropfile))
    assert len(parsed) == 1
    assert parsed[0]['op'] == 'sub'
    assert parsed[0]['dst'] == 'rax'
    assert parsed[0]['src'] == '-1'


def test_parse_hyphenated_operation_name(x64, tmp_path):
    '''
    Regression (#38): an operation whose name contains a hyphen (e.g. jmp-rel)
    must be parsed. Before the fix REGEX_OP did not allow '-' in the operation
    name and the line failed with "Unable to parse operation". jmp-rel is a
    composite operation, so it expands into its concrete steps.
    '''
    ropfile = tmp_path / 'chain.txt'
    ropfile.write_text('jmp-rel(rax)\n')
    parsed = RopChain(None)._parse_ropfile(str(ropfile))
    assert parsed
    assert all(op['op'] != 'jmp-rel' for op in parsed)


def test_store_dst_does_not_clear_clobbered_address_register(x64):
    '''
    Regression (#36): a store `st(rbx, rax)` is `mov [rbx], rax`, where rbx is
    the address base register (read, not written). It must NOT refresh rbx's
    clobber state.

    Step 1 `lc(rcx)` uses `pop rcx ; pop rbx ; ret`, which clobbers rbx.
    Step 2 `st(rbx, rax)` reads rbx as an address; before the fix it wrongly
    cleared rbx's clobber, so step 3 `mov(rdx, rbx)` (which reads rbx) was
    allowed and an invalid chain was produced. After the fix rbx stays
    clobbered and no chain is found.
    '''
    gadgets = [
        make_gadget(b'\x59\x5b\xc3', 0x1000),       # pop rcx ; pop rbx ; ret
        make_gadget(b'\x48\x89\x03\xc3', 0x1010),   # mov [rbx], rax ; ret
        make_gadget(b'\x48\x89\xda\xc3', 0x1020),   # mov rdx, rbx ; ret
    ]
    chain = [
        _op('lc', dst='rcx'),
        _op('st', dst='rbx', src='rax'),
        _op('mov', dst='rdx', src='rbx'),
    ]
    with pytest.raises(ropchain_mod.RopChainNotFound):
        list(RopChain(None).search(gadgets, chain))
