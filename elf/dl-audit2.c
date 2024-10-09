
#include <assert.h>
#include <link.h>
#include <ldsodefs.h>

// =================================================================================
// qemu-nc/loaderapi.h

#define X64NC_MAGIC_SYSCALL_INDEX 114514

enum X64NC_MAGIC_SYSCALL_TYPE
{
  X64NC_CheckHealth = 0,

  X64NC_LoadLibrary = 0x1,
  X64NC_FreeLibrary,
  X64NC_GetProcAddress,
  X64NC_GetErrorMessage,
  X64NC_CallNativeProc,
  X64NC_WaitForFinished,

  X64NC_LA_ObjOpen,
  X64NC_LA_ObjClose,
  X64NC_LA_PreInit,
  X64NC_LA_SymBind,

  X64NC_RegisterCallThunk,
};

// =================================================================================

// =================================================================================
// qemu-nc/syscall_helper.h

static inline uint64_t
syscall1 (uint64_t syscall_number, void *arg)
{
  uint64_t ret;
  __asm__ volatile ("movq %1, %%rax\n\t" // 加载系统调用号到 rax
		    "movq %2, %%rdi\n\t" // 加载参数到 rdi
		    "syscall\n\t"	 // 执行系统调用
		    "movq %%rax, %0\n\t" // 将返回值存储在 ret 中
		    : "=r"(ret)		 // 输出列表
		    : "r"(syscall_number), "r"(arg) // 输入列表
		    : "%rax", "%rdi", "memory" // 被改变的寄存器列表
  );
  return ret;
}

static inline uint64_t
syscall2 (uint64_t syscall_number, void *arg1, void *arg2)
{
  uint64_t ret;
  __asm__ volatile ("mov %1, %%rax\n" // 系统调用号放入rax
		    "mov %2, %%rdi\n" // 第一个参数arg1放入rdi
		    "mov %3, %%rsi\n" // 第二个参数arg2放入rsi
		    "syscall\n"	      // 执行系统调用
		    "mov %%rax, %0"   // 系统调用返回值放入result
		    : "=r"(ret)	      // 输出操作数
		    : "r"(syscall_number), "r"(arg1), "r"(arg2) // 输入操作数
		    : "%rax", "%rdi", "%rsi", "memory" // 被修改寄存器列表
  );
  return ret;
}

// =================================================================================

enum MagicAuditInfo
{
  Unchecked = 0,
  Supported,
  NotSupported,
};

struct MagicAuditContext
{
  enum MagicAuditInfo info;
};

static struct MagicAuditContext g_audit_ctx;

static bool
magic_audit_check_supported (void)
{
  if (__glibc_likely (g_audit_ctx.info == Supported))
    return true;

  if (g_audit_ctx.info == Unchecked)
    {
      long ret = (long) syscall1 (X64NC_MAGIC_SYSCALL_INDEX,
				  (void *) X64NC_CheckHealth);
      if (ret == -ENOSYS)
	{
	  // g_audit_ctx.info = NotSupported;
	  // return false;
	}
      g_audit_ctx.info = Supported;
      return true;
    }

  return false;
}

static unsigned int
magic_audit_objopen (struct link_map *l, Lmid_t lmid, uintptr_t *cookie,
		     const char *target)
{
  unsigned int ret = 0;
  void *a[] = {
    l, (void *) lmid, cookie, (void *) target, &ret,
  };
  (void) syscall2 (X64NC_MAGIC_SYSCALL_INDEX, (void *) X64NC_LA_ObjOpen, a);
  return ret;
}

static unsigned int
magic_audit_objclose (struct link_map *l, uintptr_t *cookie)
{
  unsigned int ret = 0;
  void *a[] = {
    l,
    cookie,
    &ret,
  };
  (void) syscall2 (X64NC_MAGIC_SYSCALL_INDEX, (void *) X64NC_LA_ObjClose, a);
  return ret;
}

static unsigned int
magic_audit_preinit (struct link_map *l, uintptr_t *cookie)
{
  unsigned int ret = 0;
  void *a[] = {
    l,
    cookie,
    &ret,
  };
  (void) syscall2 (X64NC_MAGIC_SYSCALL_INDEX, (void *) X64NC_LA_PreInit, a);
  return ret;
}

static uintptr_t
magic_audit_symbind64 (Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook,
		       uintptr_t *defcook, unsigned int *flags,
		       const char *symname)
{
  uintptr_t ret = 0;
  void *a[] = {
    sym,   (void *) (uintptr_t) ndx, refcook, defcook,
    flags, (void *) symname,	     &ret,
  };
  (void) syscall2 (X64NC_MAGIC_SYSCALL_INDEX, (void *) X64NC_LA_SymBind, a);
  return ret;
}

// ===

void
_dl_audit_objopen_x64nc (struct link_map *l, Lmid_t nsid, const char *target)
{
  if (!__glibc_likely (magic_audit_check_supported ()))
    return;

  (void) magic_audit_objopen (l, nsid, NULL, target);
}

void
_dl_audit_objclose_x64nc (struct link_map *l)
{
  if (!__glibc_likely (magic_audit_check_supported ())
      || GL (dl_ns)[l->l_ns]._ns_loaded->l_auditing)
    return;

  (void) magic_audit_objclose (l, NULL);
}

void
_dl_audit_preinit_x64nc (struct link_map *l)
{
  if (!__glibc_likely (magic_audit_check_supported ()))
    return;

  (void) magic_audit_preinit (l, NULL);
}

void
_dl_audit_symbind_x64nc (struct link_map *l, const void *reloc,
			 const ElfW (Sym) * defsym, DL_FIXUP_VALUE_TYPE *value,
			 lookup_t result, bool lazy)
{
  if (!__glibc_likely (magic_audit_check_supported ()))
    return;

  /* Compute index of the symbol entry in the symbol table of the DSO
     with the definition.  */
  unsigned int boundndx
      = defsym - (ElfW (Sym) *) D_PTR (result, l_info[DT_SYMTAB]);

  /* Synthesize a symbol record where the st_value field is the result.  */
  ElfW (Sym) sym = *defsym;
  sym.st_value = DL_FIXUP_VALUE_ADDR (*value);

  /* Keep track whether there is any interest in tracing the call in the lower
     two bits.  */
  // assert (DL_NNS * 2 <= sizeof (reloc_result->flags) * 8);
  assert ((LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT) == 3);

  const char *strtab2 = (const void *) D_PTR (result, l_info[DT_STRTAB]);

  unsigned int flags = 0;
  uintptr_t new_value = (uintptr_t) sym.st_value;

  flags |= LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT;
  new_value = magic_audit_symbind64 (&sym, boundndx, NULL, NULL, &flags,
				     strtab2 + defsym->st_name);
  if (new_value != 0 && new_value != (uintptr_t) sym.st_value)
    {
      flags |= LA_SYMB_ALTVALUE;
      sym.st_value = DL_FIXUP_BINDNOW_ADDR_VALUE (new_value);
    }

  if (flags & LA_SYMB_ALTVALUE)
    DL_FIXUP_BINDNOW_RELOC (l, reloc, value, new_value, sym.st_value, lazy);
}

void
_dl_audit_symbind_alt_x64nc (struct link_map *l, const ElfW (Sym) * ref,
			     void **value, lookup_t result)
{
  if (!__glibc_likely (magic_audit_check_supported ()))
    return;

  const char *strtab = (const char *) D_PTR (result, l_info[DT_STRTAB]);
  /* Compute index of the symbol entry in the symbol table of the DSO with
     the definition.  */
  unsigned int ndx = (ref - (ElfW (Sym) *) D_PTR (result, l_info[DT_SYMTAB]));

  unsigned int altvalue = 0;
  /* Synthesize a symbol record where the st_value field is the result.  */
  ElfW (Sym) sym = *ref;
  sym.st_value = (ElfW (Addr)) * value;

  unsigned int flags = altvalue | LA_SYMB_DLSYM;
  uintptr_t new_value = magic_audit_symbind64 (&sym, ndx, NULL, NULL, &flags,
					       strtab + ref->st_name);
  if (new_value != (uintptr_t) sym.st_value)
    {
      altvalue = LA_SYMB_ALTVALUE;
      sym.st_value = new_value;
    }

  *value = (void *) sym.st_value;
}
rtld_hidden_def (_dl_audit_symbind_alt_x64nc)