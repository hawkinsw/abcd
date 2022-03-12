        global _start
        extern puts

        section .data
hello:  db "Hello, ASM!", 10

        section .text
_start: mov rdi, hello ; the first parameter to `puts` is the string to print.
                       ; Calling conventions say that 1st param always goes
                       ; in rdi
				jmp 10
				mov r8, 0xb8419090
        call puts      ; call puts
				jmp -8
        ;-----
        mov rax, 60    ; 60 is the system call for exit
        xor rdi, rdi   ; set the return value of the process to 0.
        syscall        ; now, tell the OS that we actually want to do a syscall.
