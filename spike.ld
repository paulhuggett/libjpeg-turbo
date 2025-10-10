OUTPUT_ARCH( "riscv" )
ENTRY(_start)


MEMORY {
  ram(xrw) : ORIGIN = 0x80000000, LENGTH = 0x1000000
}
SECTIONS {
  __stack = ORIGIN(ram) + LENGTH(ram);

  /* Discard allocatable sections we don't need */
  /DISCARD/ : {
    *(.dynsym)
    *(.gnu.hash)
    *(.hash)
    *(.dynstr)
    *(.dynamic)
  }
  .init ALIGN(4) : {
    KEEP (*(.text.init.enter))
    KEEP (*(.data.init.enter))
    KEEP (*(SORT_BY_NAME(.init) SORT_BY_NAME(.init.*)))
  } > ram

  .text : {
    /* code */
    *(.text.unlikely .text.unlikely.*)
    *(.text.startup .text.startup.*)
    *(.text .text.* .opd .opd.*)
    *(.gnu.linkonce.t.*)
    KEEP (*(.fini .fini.*))
    __text_end = .;

    PROVIDE (__etext = __text_end);
    PROVIDE (_etext = __text_end);
    PROVIDE (etext = __text_end);

    /* Need to pre-align so that the symbols come after padding */
    . = ALIGN(8);

    /* lists of constructors and destructors */
    PROVIDE_HIDDEN ( __preinit_array_start = . );
    KEEP (*(.preinit_array))
    PROVIDE_HIDDEN ( __preinit_array_end = . );

    PROVIDE_HIDDEN ( __init_array_start = . );
    KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
    KEEP (*(.init_array .ctors))
    PROVIDE_HIDDEN ( __init_array_end = . );

    PROVIDE_HIDDEN ( __fini_array_start = . );
    KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
    KEEP (*(.fini_array .dtors))
    PROVIDE_HIDDEN ( __fini_array_end = . );
  } > ram

  .rodata : {
    /* read-only data */
    *(.rdata)
    *(.rodata .rodata.*)
    *(.gnu.linkonce.r.*)

    *(.srodata.cst16)
    *(.srodata.cst8)
    *(.srodata.cst4)
    *(.srodata.cst2)
    *(.srodata .srodata.*)
  } > ram

  .data.rel.ro : {
    /* data that needs relocating */
    *(.data.rel.ro .data.rel.ro.*)
  } > ram

  /* Thread Local Storage sections  */
  .tdata : { *(.tdata .tdata.* .gnu.linkonce.td.*) }
  .tbss  : { *(.tbss .tbss.* .gnu.linkonce.tb.*) *(.tcommon) }
  __tls_base = ADDR(.tdata);

  .got : {
    *(.got.plt)
    *(.got)
  } > ram

  .toc : {
    *(.toc .toc.*)
  } > ram

  .data : {
    *(.data .data.*)
    *(.gnu.linkonce.d.*)
    	/* Need to pre-align so that the symbols come after padding */
    . = ALIGN(8);

    PROVIDE( __global_pointer$ = . + 0x800 );
    PROVIDE( _gp = . + 0x8000);
    *(.sdata .sdata.* .sdata2.*)
    *(.gnu.linkonce.s.*)
  } > ram
  PROVIDE(__data_start = ADDR(.data));
  PROVIDE(__data_source = LOADADDR(.data));
  __data_size = SIZEOF(.data);
  

  .bss (NOLOAD) : {
    __bss_start = .;
    *(.sbss*)
    *(.gnu.linkonce.sb.*)
    *(.bss .bss.*)
    *(.gnu.linkonce.b.*)
    *(COMMON)

    /* Align the heap */
    . = ALIGN(8);
    __bss_end = .;
  } >ram
  __end = __bss_end;
  _end = __bss_end;
  /*PROVIDE(end = __bss_end);*/
  __bss_size = __bss_end - __bss_start;

  /* Make the rest of memory available for heap storage */
  __heap_start = __end;
  __heap_end = __stack - (DEFINED(__stack_size) ? __stack_size : 0x00001000);
  __heap_size = __heap_end - __heap_start;

  /* Allow a minimum heap size to be specified */
  .heap (NOLOAD) : {
    . += (DEFINED(__heap_size_min) ? __heap_size_min : 0);
  } > ram

  /* Define a stack region to make sure it fits in memory */
  .stack (NOLOAD) : {
    . += (DEFINED(__stack_size) ? __stack_size : 0x00001000);
  } >ram
}
