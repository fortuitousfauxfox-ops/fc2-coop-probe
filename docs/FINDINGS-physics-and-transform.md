# Physics off, and driving the entity transform

Research notes for the co-op prototype, 2026-11-11/12. They extend
[HOW-IT-WORKS.md](HOW-IT-WORKS.md) with the collision and transform work done after it was
written. Every address is for the Steam 1.03 build of `Dunia.dll`
(SHA-256 `6353936a54aa841350bb30ff005727859cdef1aa10c209209b220b399e862765`, 20,183,176 bytes).

The labels below separate what was observed in a test copy, what is derived from it, and what is
still unknown.

## Why

A puppet spawned from Lua as a `PawnPlayer` is solid: it pushes the local player and the game
can resolve contact as impact damage. It also shows the generic hand/talk interaction prompt.
Making the local player invincible is the wrong fix; the puppet does not need collision at all.

## The physics component

`findbody` returns the Havok body (a wrapper around `...`, vtable `0x10E67658`). The physics
component is not reachable from it directly. The chain is:

```
Havok body  -- [+0xC] -->  holder  -- [+0xC] -->  CCharacterPhysComponent
holder is also [component + 0x160]
```

`CCharacterPhysComponent` (live vtable `0x10E72FE0`; `+4` holds the class metadata
`0x10E72FD0`, which must not be mistaken for the object start):

| Offset | Meaning |
|---|---|
| `+0x160` | primary physics holder (vtable `0x10E65B58`) |
| `+0x164` | second holder (vtable `0x10E65D48`) |
| `+0x178` | state enum |
| `+0x1B4` | `PhysicsEnabled` |
| `+0x1B5` | second collision flag |

The getter `0x105442C0` is exactly `mov al,[ecx+0x1B4]; ret`, which identifies the class.

## Turning physics off

Writing `+0x1B4 = 0` directly is **not** enough: the cached field changes but the Havok body
keeps colliding (measured: 0.404 m push against a 0.402 m control).

The real setter is `0x105446B0(component, bool)`. It writes `+0x1B4` and, for states 0/2/3/5,
tail-jumps into the primary holder's virtual `+0x8C` (`0x10493980`, which cleans one stack
argument with `ret 4`). Call it through a `ret 4` thunk; a plain `ret` thunk leaves the stack
off by one dword for those states.

Observed (test copy, one player, one puppet):

- physics on: placing the puppet body on the player ejected the player about 0.402 m;
- `0x105446B0(component, 0)` then read back as `en 0/1`, the flag stayed off, and the same
  overlap ejected the player **0.000 m**;
- the owner confirmed the puppet phases through the player, renders in its normal standing
  pose, and shows no interaction prompt;
- re-enabling with `1` returned the Havok body and read `en 1/1`.

## What physics-off costs: the visual freezes

With physics off, writing the Havok body matrix translation moves neither the rendered puppet
nor the entity transform at `entity+0x60`. The visual follows the entity transform, which
physics normally feeds.

`0x60` is not an independent sync source. It is row 3 of the entity's 4x4 transform at
`entity+0x30..+0x6F`.

## The engine's own transform setter: `0x104DF440`

Found with a gdb hardware write watchpoint on the puppet's `entity+0x60`, triggered by forcing
a body-matrix write with physics on. gdb stopped at `0x104DF4D5`:

```
movaps %xmm0,0x30(%edi)      ; edi = esi+0x30, esi = entity object
```

That store is the fourth `movaps` of the function at **`0x104DF440`**:

- `this = ecx` (the entity object);
- `[ebp+8] = matrix*`, 16-byte aligned (the copies use `movaps`);
- `[ebp+0xc] = skipEntity`;
- `ret 8`;
- copies four rows from `matrix*` to `this+0x30..+0x6F`, so the entity translation at `+0x60`
  is row 3 of the source matrix;
- then walks the attached list at `+0x9c/+0xa0` and marks the transform dirty.

It is not in the entity vtable (`0x10E0DFDC`), so it is a non-virtual method.

Derived: with physics off, call `0x104DF440(entity, matrix, 0)` and source the matrix from the
Havok body, whose translation is at `mat+0x30`. The body-to-entity copy is what physics normally
does, so a manual call should reproduce a physical move.

Unknown / not yet verified:

- whether a manual `0x104DF440` call while physics is off moves the rendered puppet (the direct
  call has been built but not run);
- whether the second argument should be `0` or a specific entity to skip;
- whether attached bones and render transforms follow a manual call with physics off.

## Collision switches that do not replace physics-off

- `SetToScriptedCollisionGroup('<id>')` (the cutscene collision group) left the player pushed
  about 1.082 m on overlap. It is not a substitute.
- `0x10544730(component, bool)` is not a collision-only switch. It writes `+0x1B5`, always calls
  the second holder's virtual `+0x8C` (`0x10494480`, `ret 4`), then conditionally the primary
  holder's virtual `+0x8C`; both reach the same primary physics virtual that `PhysicsEnabled=0`
  drives, so it also stops the visual.
- Poking the wrapper's `+0x2C` collision filter, or the body/phantom `+0x2C` filter, did not
  disable collision (the cached values are not consumed the way the field name suggests).

## Call primitives added to the probe

`GCC` on i386 silently ignores `__attribute__((thiscall))` in C, so engine methods are called
through hand-built machine-code thunks:

| Command | Convention |
|---|---|
| `call1 <fn> <self> <arg>` | one stack arg, caller cleans |
| `call1r4 <fn> <self> <arg>` | one stack arg, callee `ret 4` |
| `call2r8 <fn> <self> <a1> <a2>` | two stack args, callee `ret 8` (used by `0x104DF440`) |

`<fn>` may be an RVA below `0x1000000` (the module base is added) or an absolute VA.

Diagnostics: `physfind <holder>`, `physget <holder>`, `physset <holder> <0|1>`,
`physcall <holder> <0|1>` (the engine setter; unsafe for state 0, use `call1r4`), plus the
interaction-monitor commands `ignore`, `ignoreoff`, `imode`, `ihits`, `itarget`.

## Reproducing the measurement

1. Start a test copy with `scripts/probe-shell.ps1 -Copy <copy> -SpawnPuppet -KeepOpen`.
2. `ent <puppet id> 0` -> entity object; `findbody <puppet id>` -> Havok body and matrix.
3. Read `body+0xC` -> holder; `physget <holder>` -> component and `en` flags.
4. Place the body on the player and record how far the player is pushed (control).
5. `call1r4 5446B0 <component> 0`; confirm `en 0/1`; repeat the push (expected 0.000 m).
6. To test the transform path, write a moved translation to `matrix+0x30`, then
   `call2r8 104DF440 <entity> <matrix> 0`, and read `entity+0x60`.

Watchpoint method: attach gdb, `watch *(unsigned int*)<entity+0x60>`, force a body-matrix write
with physics on, and inspect the stopping `movaps` and its base register.

## Safety

The runs behind these notes did not write a save. The real profile and both test profiles kept
their pristine save hash, and the launcher reported the real profile unchanged
(`new 0, changed 0, removed 0`).

## Merge status

These diagnostics and notes were merged into this tree on top of the existing prototype. The
merged `probe.c` compiles with the documented build command (32-bit MinGW; 270,634-byte
`dinput8.dll`) and contains no conflict markers. It has **not** been run in-game yet, so
re-run `tests/two_copy_walk.ps1` before relying on this build for the prototype's existing
features.
