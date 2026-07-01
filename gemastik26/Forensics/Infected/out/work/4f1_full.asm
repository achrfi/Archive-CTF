
./binary:     file format binary


Disassembly of section .data:

00000000000004f1 <.data+0x4f1>:
     4f1:	55                   	push   %rbp
     4f2:	31 c0                	xor    %eax,%eax
     4f4:	48 89 e5             	mov    %rsp,%rbp
     4f7:	41 57                	push   %r15
     4f9:	41 56                	push   %r14
     4fb:	41 55                	push   %r13
     4fd:	41 54                	push   %r12
     4ff:	49 89 cc             	mov    %rcx,%r12
     502:	b9 06 00 00 00       	mov    $0x6,%ecx
     507:	57                   	push   %rdi
     508:	56                   	push   %rsi
     509:	53                   	push   %rbx
     50a:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
     50e:	48 81 ec f0 00 00 00 	sub    $0xf0,%rsp
     515:	48 89 55 18          	mov    %rdx,0x18(%rbp)
     519:	48 8d 7c 24 58       	lea    0x58(%rsp),%rdi
     51e:	44 89 45 20          	mov    %r8d,0x20(%rbp)
     522:	f3 ab                	rep stos %eax,(%rdi)
     524:	48 8d 7c 24 70       	lea    0x70(%rsp),%rdi
     529:	b9 20 00 00 00       	mov    $0x20,%ecx
     52e:	c7 44 24 54 04 00 00 	movl   $0x4,0x54(%rsp)
     535:	00 
     536:	f3 ab                	rep stos %eax,(%rdi)
     538:	4c 89 e1             	mov    %r12,%rcx
     53b:	e8 6c ff ff ff       	call   0x4ac
     540:	48 85 c0             	test   %rax,%rax
     543:	0f 84 80 02 00 00    	je     0x7c9
     549:	44 8b 45 20          	mov    0x20(%rbp),%r8d
     54d:	48 8d 5c 24 58       	lea    0x58(%rsp),%rbx
     552:	48 89 c2             	mov    %rax,%rdx
     555:	49 89 c5             	mov    %rax,%r13
     558:	48 8d 74 24 70       	lea    0x70(%rsp),%rsi
     55d:	48 89 d9             	mov    %rbx,%rcx
     560:	e8 4b 04 00 00       	call   0x9b0
     565:	48 89 d9             	mov    %rbx,%rcx
     568:	e8 99 04 00 00       	call   0xa06
     56d:	48 89 d9             	mov    %rbx,%rcx
     570:	88 44 24 3f          	mov    %al,0x3f(%rsp)
     574:	e8 d4 04 00 00       	call   0xa4d
     579:	48 89 d9             	mov    %rbx,%rcx
     57c:	89 c7                	mov    %eax,%edi
     57e:	e8 ca 04 00 00       	call   0xa4d
     583:	48 89 d9             	mov    %rbx,%rcx
     586:	89 44 24 44          	mov    %eax,0x44(%rsp)
     58a:	e8 be 04 00 00       	call   0xa4d
     58f:	48 89 d9             	mov    %rbx,%rcx
     592:	48 c7 84 24 a8 00 00 	movq   $0x0,0xa8(%rsp)
     599:	00 00 00 00 00 
     59e:	89 44 24 40          	mov    %eax,0x40(%rsp)
     5a2:	e8 a6 04 00 00       	call   0xa4d
     5a7:	48 89 f2             	mov    %rsi,%rdx
     5aa:	48 89 d9             	mov    %rbx,%rcx
     5ad:	89 84 24 a0 00 00 00 	mov    %eax,0xa0(%rsp)
     5b4:	e8 ee 04 00 00       	call   0xaa7
     5b9:	48 8d 56 10          	lea    0x10(%rsi),%rdx
     5bd:	48 89 d9             	mov    %rbx,%rcx
     5c0:	48 89 44 24 78       	mov    %rax,0x78(%rsp)
     5c5:	e8 dd 04 00 00       	call   0xaa7
     5ca:	48 89 d9             	mov    %rbx,%rcx
     5cd:	48 89 84 24 88 00 00 	mov    %rax,0x88(%rsp)
     5d4:	00 
     5d5:	48 8d 46 20          	lea    0x20(%rsi),%rax
     5d9:	48 89 c2             	mov    %rax,%rdx
     5dc:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
     5e1:	e8 c1 04 00 00       	call   0xaa7
     5e6:	48 8d 56 40          	lea    0x40(%rsi),%rdx
     5ea:	48 89 d9             	mov    %rbx,%rcx
     5ed:	48 89 84 24 98 00 00 	mov    %rax,0x98(%rsp)
     5f4:	00 
     5f5:	e8 ad 04 00 00       	call   0xaa7
     5fa:	48 89 d9             	mov    %rbx,%rcx
     5fd:	48 89 84 24 b8 00 00 	mov    %rax,0xb8(%rsp)
     604:	00 
     605:	48 8d 46 50          	lea    0x50(%rsi),%rax
     609:	48 89 c2             	mov    %rax,%rdx
     60c:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
     611:	e8 91 04 00 00       	call   0xaa7
     616:	48 8d 56 60          	lea    0x60(%rsi),%rdx
     61a:	48 89 d9             	mov    %rbx,%rcx
     61d:	48 89 84 24 c8 00 00 	mov    %rax,0xc8(%rsp)
     624:	00 
     625:	e8 7d 04 00 00       	call   0xaa7
     62a:	48 89 d9             	mov    %rbx,%rcx
     62d:	48 89 84 24 d8 00 00 	mov    %rax,0xd8(%rsp)
     634:	00 
     635:	48 8d 46 70          	lea    0x70(%rsi),%rax
     639:	48 89 c2             	mov    %rax,%rdx
     63c:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
     641:	e8 61 04 00 00       	call   0xaa7
     646:	8b 4c 24 70          	mov    0x70(%rsp),%ecx
     64a:	48 89 84 24 e8 00 00 	mov    %rax,0xe8(%rsp)
     651:	00 
     652:	e8 d8 fb ff ff       	call   0x22f
     657:	31 d2                	xor    %edx,%edx
     659:	41 b9 00 30 00 00    	mov    $0x3000,%r9d
     65f:	4c 89 e1             	mov    %r12,%rcx
     662:	44 8b b4 24 90 00 00 	mov    0x90(%rsp),%r14d
     669:	00 
     66a:	44 03 b4 24 80 00 00 	add    0x80(%rsp),%r14d
     671:	00 
     672:	44 03 b4 24 a0 00 00 	add    0xa0(%rsp),%r14d
     679:	00 
     67a:	41 01 c6             	add    %eax,%r14d
     67d:	8b 44 24 54          	mov    0x54(%rsp),%eax
     681:	45 8d 3c fe          	lea    (%r14,%rdi,8),%r15d
     685:	45 89 f8             	mov    %r15d,%r8d
     688:	89 44 24 20          	mov    %eax,0x20(%rsp)
     68c:	e8 14 05 00 00       	call   0xba5
     691:	48 85 c0             	test   %rax,%rax
     694:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
     699:	0f 84 2a 01 00 00    	je     0x7c9
     69f:	45 89 f8             	mov    %r15d,%r8d
     6a2:	48 89 c2             	mov    %rax,%rdx
     6a5:	48 89 d9             	mov    %rbx,%rcx
     6a8:	e8 03 03 00 00       	call   0x9b0
     6ad:	44 89 f2             	mov    %r14d,%edx
     6b0:	48 89 d9             	mov    %rbx,%rcx
     6b3:	e8 d0 03 00 00       	call   0xa88
     6b8:	48 89 d9             	mov    %rbx,%rcx
     6bb:	49 89 c7             	mov    %rax,%r15
     6be:	e8 0b 03 00 00       	call   0x9ce
     6c3:	48 89 d9             	mov    %rbx,%rcx
     6c6:	89 c2                	mov    %eax,%edx
     6c8:	e8 bb 03 00 00       	call   0xa88
     6cd:	48 89 f2             	mov    %rsi,%rdx
     6d0:	4c 89 f9             	mov    %r15,%rcx
     6d3:	49 89 c6             	mov    %rax,%r14
     6d6:	e8 6d fb ff ff       	call   0x248
     6db:	48 8d 56 70          	lea    0x70(%rsi),%rdx
     6df:	48 8d 4e 20          	lea    0x20(%rsi),%rcx
     6e3:	e8 92 fd ff ff       	call   0x47a
     6e8:	48 8d 56 70          	lea    0x70(%rsi),%rdx
     6ec:	48 8d 4e 50          	lea    0x50(%rsi),%rcx
     6f0:	e8 85 fd ff ff       	call   0x47a
     6f5:	0f b6 54 24 3f       	movzbl 0x3f(%rsp),%edx
     6fa:	41 89 f9             	mov    %edi,%r9d
     6fd:	49 89 f0             	mov    %rsi,%r8
     700:	4c 89 74 24 20       	mov    %r14,0x20(%rsp)
     705:	4c 89 e1             	mov    %r12,%rcx
     708:	e8 54 fc ff ff       	call   0x361
     70d:	85 c0                	test   %eax,%eax
     70f:	0f 84 b4 00 00 00    	je     0x7c9
     715:	8b 4c 24 70          	mov    0x70(%rsp),%ecx
     719:	e8 11 fb ff ff       	call   0x22f
     71e:	48 8b 54 24 78       	mov    0x78(%rsp),%rdx
     723:	41 b9 20 00 00 00    	mov    $0x20,%r9d
     729:	4c 89 e1             	mov    %r12,%rcx
     72c:	41 89 c0             	mov    %eax,%r8d
     72f:	48 8d 44 24 54       	lea    0x54(%rsp),%rax
     734:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
     739:	e8 de 04 00 00       	call   0xc1c
     73e:	85 c0                	test   %eax,%eax
     740:	0f 84 83 00 00 00    	je     0x7c9
     746:	45 31 c0             	xor    %r8d,%r8d
     749:	4c 89 ea             	mov    %r13,%rdx
     74c:	41 b9 00 80 00 00    	mov    $0x8000,%r9d
     752:	4c 89 e1             	mov    %r12,%rcx
     755:	e8 93 04 00 00       	call   0xbed
     75a:	8b 54 24 40          	mov    0x40(%rsp),%edx
     75e:	4d 89 f1             	mov    %r14,%r9
     761:	41 89 f8             	mov    %edi,%r8d
     764:	48 89 f1             	mov    %rsi,%rcx
     767:	e8 c8 fc ff ff       	call   0x434
     76c:	4c 63 6d 20          	movslq 0x20(%rbp),%r13
     770:	41 b8 05 00 00 00    	mov    $0x5,%r8d
     776:	48 89 d9             	mov    %rbx,%rcx
     779:	48 8b 55 18          	mov    0x18(%rbp),%rdx
     77d:	4c 01 ea             	add    %r13,%rdx
     780:	e8 2b 02 00 00       	call   0x9b0
     785:	48 89 d9             	mov    %rbx,%rcx
     788:	e8 c0 02 00 00       	call   0xa4d
     78d:	31 d2                	xor    %edx,%edx
     78f:	48 89 d9             	mov    %rbx,%rcx
     792:	85 c0                	test   %eax,%eax
     794:	89 c7                	mov    %eax,%edi
     796:	0f 95 c2             	setne  %dl
     799:	e8 ea 02 00 00       	call   0xa88
     79e:	44 8b 4c 24 44       	mov    0x44(%rsp),%r9d
     7a3:	49 89 f0             	mov    %rsi,%r8
     7a6:	89 fa                	mov    %edi,%edx
     7a8:	4c 03 4c 24 78       	add    0x78(%rsp),%r9
     7ad:	48 89 c1             	mov    %rax,%rcx
     7b0:	41 ff d1             	call   *%r9
     7b3:	48 8b 54 24 48       	mov    0x48(%rsp),%rdx
     7b8:	45 31 c0             	xor    %r8d,%r8d
     7bb:	4c 89 e1             	mov    %r12,%rcx
     7be:	41 b9 00 80 00 00    	mov    $0x8000,%r9d
     7c4:	e8 24 04 00 00       	call   0xbed
