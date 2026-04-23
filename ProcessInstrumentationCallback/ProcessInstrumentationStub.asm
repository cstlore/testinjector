; ProcessInstrumentationStub.asm
; x64 instrumentation callback gate with runtime AVX/SSE selection.
; Kernel supplies:
;   R10 = original user-mode continuation RIP
;   RAX = syscall status/result

.code

EXTERN g_InstrumentationUseAvx:BYTE
EXTERN InstrumentationShouldRun:PROC
EXTERN InstrumentationRunPayload:PROC
PUBLIC ProcessInstrumentationStub

; Common stack layout after `sub rsp, 268h`:
; 00h..1Fh  : shadow space
; 20h..57h  : GPR saves (RAX,RCX,RDX,R8,R9,R10,R11)
; 60h..15Fh : XMM0..XMM15 saves (SSE path)
; 60h..25Fh : YMM0..YMM15 saves (AVX path)
;
; RSP alignment:
;   entry rsp % 16 == 8, after sub 268h => rsp % 16 == 0
ProcessInstrumentationStub PROC FRAME
    sub     rsp, 268h
    .allocstack 268h
    .endprolog

    mov     [rsp + 20h], rax
    mov     [rsp + 28h], rcx
    mov     [rsp + 30h], rdx
    mov     [rsp + 38h], r8
    mov     [rsp + 40h], r9
    mov     [rsp + 48h], r10
    mov     [rsp + 50h], r11

    cmp     byte ptr [g_InstrumentationUseAvx], 0
    jne     AvxPath

SsePath:
    movdqu  xmmword ptr [rsp + 060h], xmm0
    movdqu  xmmword ptr [rsp + 070h], xmm1
    movdqu  xmmword ptr [rsp + 080h], xmm2
    movdqu  xmmword ptr [rsp + 090h], xmm3
    movdqu  xmmword ptr [rsp + 0A0h], xmm4
    movdqu  xmmword ptr [rsp + 0B0h], xmm5
    movdqu  xmmword ptr [rsp + 0C0h], xmm6
    movdqu  xmmword ptr [rsp + 0D0h], xmm7
    movdqu  xmmword ptr [rsp + 0E0h], xmm8
    movdqu  xmmword ptr [rsp + 0F0h], xmm9
    movdqu  xmmword ptr [rsp + 100h], xmm10
    movdqu  xmmword ptr [rsp + 110h], xmm11
    movdqu  xmmword ptr [rsp + 120h], xmm12
    movdqu  xmmword ptr [rsp + 130h], xmm13
    movdqu  xmmword ptr [rsp + 140h], xmm14
    movdqu  xmmword ptr [rsp + 150h], xmm15

    call    InstrumentationShouldRun
    test    al, al
    je      short RestoreSse

    mov     rcx, [rsp + 48h]
    mov     rdx, [rsp + 20h]
    call    InstrumentationRunPayload

RestoreSse:
    movdqu  xmm0, xmmword ptr [rsp + 060h]
    movdqu  xmm1, xmmword ptr [rsp + 070h]
    movdqu  xmm2, xmmword ptr [rsp + 080h]
    movdqu  xmm3, xmmword ptr [rsp + 090h]
    movdqu  xmm4, xmmword ptr [rsp + 0A0h]
    movdqu  xmm5, xmmword ptr [rsp + 0B0h]
    movdqu  xmm6, xmmword ptr [rsp + 0C0h]
    movdqu  xmm7, xmmword ptr [rsp + 0D0h]
    movdqu  xmm8, xmmword ptr [rsp + 0E0h]
    movdqu  xmm9, xmmword ptr [rsp + 0F0h]
    movdqu  xmm10, xmmword ptr [rsp + 100h]
    movdqu  xmm11, xmmword ptr [rsp + 110h]
    movdqu  xmm12, xmmword ptr [rsp + 120h]
    movdqu  xmm13, xmmword ptr [rsp + 130h]
    movdqu  xmm14, xmmword ptr [rsp + 140h]
    movdqu  xmm15, xmmword ptr [rsp + 150h]
    jmp     RestoreAndReturn

AvxPath:
    vmovdqu ymmword ptr [rsp + 060h], ymm0
    vmovdqu ymmword ptr [rsp + 080h], ymm1
    vmovdqu ymmword ptr [rsp + 0A0h], ymm2
    vmovdqu ymmword ptr [rsp + 0C0h], ymm3
    vmovdqu ymmword ptr [rsp + 0E0h], ymm4
    vmovdqu ymmword ptr [rsp + 100h], ymm5
    vmovdqu ymmword ptr [rsp + 120h], ymm6
    vmovdqu ymmword ptr [rsp + 140h], ymm7
    vmovdqu ymmword ptr [rsp + 160h], ymm8
    vmovdqu ymmword ptr [rsp + 180h], ymm9
    vmovdqu ymmword ptr [rsp + 1A0h], ymm10
    vmovdqu ymmword ptr [rsp + 1C0h], ymm11
    vmovdqu ymmword ptr [rsp + 1E0h], ymm12
    vmovdqu ymmword ptr [rsp + 200h], ymm13
    vmovdqu ymmword ptr [rsp + 220h], ymm14
    vmovdqu ymmword ptr [rsp + 240h], ymm15

    call    InstrumentationShouldRun
    test    al, al
    je      short RestoreAvx

    mov     rcx, [rsp + 48h]
    mov     rdx, [rsp + 20h]
    vzeroupper
    call    InstrumentationRunPayload

RestoreAvx:
    vmovdqu ymm0, ymmword ptr [rsp + 060h]
    vmovdqu ymm1, ymmword ptr [rsp + 080h]
    vmovdqu ymm2, ymmword ptr [rsp + 0A0h]
    vmovdqu ymm3, ymmword ptr [rsp + 0C0h]
    vmovdqu ymm4, ymmword ptr [rsp + 0E0h]
    vmovdqu ymm5, ymmword ptr [rsp + 100h]
    vmovdqu ymm6, ymmword ptr [rsp + 120h]
    vmovdqu ymm7, ymmword ptr [rsp + 140h]
    vmovdqu ymm8, ymmword ptr [rsp + 160h]
    vmovdqu ymm9, ymmword ptr [rsp + 180h]
    vmovdqu ymm10, ymmword ptr [rsp + 1A0h]
    vmovdqu ymm11, ymmword ptr [rsp + 1C0h]
    vmovdqu ymm12, ymmword ptr [rsp + 1E0h]
    vmovdqu ymm13, ymmword ptr [rsp + 200h]
    vmovdqu ymm14, ymmword ptr [rsp + 220h]
    vmovdqu ymm15, ymmword ptr [rsp + 240h]

RestoreAndReturn:
    mov     r11, [rsp + 50h]
    mov     r10, [rsp + 48h]
    mov     r9,  [rsp + 40h]
    mov     r8,  [rsp + 38h]
    mov     rdx, [rsp + 30h]
    mov     rcx, [rsp + 28h]
    mov     rax, [rsp + 20h]

    add     rsp, 268h
    jmp     r10
ProcessInstrumentationStub ENDP

END
