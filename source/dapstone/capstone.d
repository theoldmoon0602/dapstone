module dapstone.capstone;

import std.exception;
import capstone.capstone;

string fromStringz(S)(S s) {
  import std.conv;
  import core.stdc.string;
  static if (is(S == char*)) {
    auto len = s.strlen();
    return s[0..len].to!string();
  } else {
    return fromStringz(s.ptr);
  }
}

static class DapstoneException : Exception
{
    mixin basicExceptionCtors;
}

struct Instruction {
  public:
    ulong addr;
    string opcode;
    string operand;
    ubyte[] bytes;
}

class Capstone {
  protected:
    csh handle;
  public:
    this(cs_arch arch, cs_mode mode) {
      if (cs_open(arch, mode, &handle) != cs_err.CS_ERR_OK) {
        throw new DapstoneException("Failed to initialize capstone ");
      }
    }
    ~this() {
      cs_close(&handle);
    }

    Instruction[] disasm(const(ubyte[]) code, ulong base_addr) {
      Instruction[] irs = [];

      cs_insn* insn;
      auto count = cs_disasm(handle, code.ptr, code.length, base_addr, 0, &insn);
      foreach (i; 0..count) {
        irs ~= Instruction(
          insn[i].address,
          insn[i].mnemonic.fromStringz(),
          insn[i].op_str.fromStringz(),
          insn[i].bytes[0..insn[i].size],
        );
      }
      cs_free(insn, count);

      return irs;
    }
}
