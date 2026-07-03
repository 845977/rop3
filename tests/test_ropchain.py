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
