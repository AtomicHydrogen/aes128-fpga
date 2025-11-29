--------------------------------------------------------------------------------
-- AES-128 Package
-- Contains all cryptographic primitives for AES encryption
--------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

package aes_pkg is
    -- Type definitions
    subtype byte_t is std_logic_vector(7 downto 0);
    subtype word_t is std_logic_vector(31 downto 0);
    subtype block_t is std_logic_vector(127 downto 0);
    type key_schedule_t is array (0 to 10) of block_t;  -- 11 round keys
    type sbox_t is array (0 to 255) of byte_t;

    -- S-box constant (shared between SubBytes and key expansion)
    constant SBOX : sbox_t := (
        x"63", x"7c", x"77", x"7b", x"f2", x"6b", x"6f", x"c5", x"30", x"01", x"67", x"2b", x"fe", x"d7", x"ab", x"76",
        x"ca", x"82", x"c9", x"7d", x"fa", x"59", x"47", x"f0", x"ad", x"d4", x"a2", x"af", x"9c", x"a4", x"72", x"c0",
        x"b7", x"fd", x"93", x"26", x"36", x"3f", x"f7", x"cc", x"34", x"a5", x"e5", x"f1", x"71", x"d8", x"31", x"15",
        x"04", x"c7", x"23", x"c3", x"18", x"96", x"05", x"9a", x"07", x"12", x"80", x"e2", x"eb", x"27", x"b2", x"75",
        x"09", x"83", x"2c", x"1a", x"1b", x"6e", x"5a", x"a0", x"52", x"3b", x"d6", x"b3", x"29", x"e3", x"2f", x"84",
        x"53", x"d1", x"00", x"ed", x"20", x"fc", x"b1", x"5b", x"6a", x"cb", x"be", x"39", x"4a", x"4c", x"58", x"cf",
        x"d0", x"ef", x"aa", x"fb", x"43", x"4d", x"33", x"85", x"45", x"f9", x"02", x"7f", x"50", x"3c", x"9f", x"a8",
        x"51", x"a3", x"40", x"8f", x"92", x"9d", x"38", x"f5", x"bc", x"b6", x"da", x"21", x"10", x"ff", x"f3", x"d2",
        x"cd", x"0c", x"13", x"ec", x"5f", x"97", x"44", x"17", x"c4", x"a7", x"7e", x"3d", x"64", x"5d", x"19", x"73",
        x"60", x"81", x"4f", x"dc", x"22", x"2a", x"90", x"88", x"46", x"ee", x"b8", x"14", x"de", x"5e", x"0b", x"db",
        x"e0", x"32", x"3a", x"0a", x"49", x"06", x"24", x"5c", x"c2", x"d3", x"ac", x"62", x"91", x"95", x"e4", x"79",
        x"e7", x"c8", x"37", x"6d", x"8d", x"d5", x"4e", x"a9", x"6c", x"56", x"f4", x"ea", x"65", x"7a", x"ae", x"08",
        x"ba", x"78", x"25", x"2e", x"1c", x"a6", x"b4", x"c6", x"e8", x"dd", x"74", x"1f", x"4b", x"bd", x"8b", x"8a",
        x"70", x"3e", x"b5", x"66", x"48", x"03", x"f6", x"0e", x"61", x"35", x"57", x"b9", x"86", x"c1", x"1d", x"9e",
        x"e1", x"f8", x"98", x"11", x"69", x"d9", x"8e", x"94", x"9b", x"1e", x"87", x"e9", x"ce", x"55", x"28", x"df",
        x"8c", x"a1", x"89", x"0d", x"bf", x"e6", x"42", x"68", x"41", x"99", x"2d", x"0f", x"b0", x"54", x"bb", x"16"
    );

    -- Round constants for key expansion
    type rcon_t is array (1 to 10) of byte_t;
    constant RCON : rcon_t := (
        x"01", x"02", x"04", x"08", x"10", x"20", x"40", x"80", x"1b", x"36"
    );

    -- Function declarations
    function sub_byte(b : byte_t) return byte_t;
    function sub_bytes(state : block_t) return block_t;
    function shift_rows(state : block_t) return block_t;
    function xtime(b : byte_t) return byte_t;
    function mix_column(col : word_t) return word_t;
    function mix_columns(state : block_t) return block_t;
    function add_round_key(state : block_t; key : block_t) return block_t;
    function sub_word(w : word_t) return word_t;
    function rot_word(w : word_t) return word_t;
    function key_expansion(key : block_t) return key_schedule_t;
    function aes_round(state : block_t; round_key : block_t; is_final : boolean) return block_t;

end package aes_pkg;

package body aes_pkg is

    ----------------------------------------------------------------------------
    -- SubBytes: Apply S-box to single byte
    ----------------------------------------------------------------------------
    function sub_byte(b : byte_t) return byte_t is
    begin
        return SBOX(to_integer(unsigned(b)));
    end function;

    ----------------------------------------------------------------------------
    -- SubBytes: Apply S-box to all 16 bytes (big-endian)
    ----------------------------------------------------------------------------
    function sub_bytes(state : block_t) return block_t is
        variable result : block_t;
    begin
        -- Byte n is at bits (127-8*n) downto (120-8*n)
        for i in 0 to 15 loop
            result(127 - 8*i downto 120 - 8*i) := sub_byte(state(127 - 8*i downto 120 - 8*i));
        end loop;
        return result;
    end function;

    ----------------------------------------------------------------------------
    -- ShiftRows: Cyclically shift rows of the state matrix
    -- State layout (byte indices, big-endian in 128-bit vector):
    --   [0  4  8  12]     Row 0: no shift
    --   [1  5  9  13]  -> Row 1: shift left 1
    --   [2  6  10 14]     Row 2: shift left 2
    --   [3  7  11 15]     Row 3: shift left 3
    ----------------------------------------------------------------------------
    function shift_rows(state : block_t) return block_t is
        variable result : block_t;
        type state_array is array (0 to 3, 0 to 3) of byte_t;
        variable s, r : state_array;
    begin
        -- Unpack state into 4x4 array (column-major, big-endian)
        -- byte n is at bits (127-8*n) downto (120-8*n)
        for col in 0 to 3 loop
            for row in 0 to 3 loop
                s(row, col) := state(127 - 32*col - 8*row downto 120 - 32*col - 8*row);
            end loop;
        end loop;

        -- Apply row shifts (shift row n left by n positions)
        for row in 0 to 3 loop
            for col in 0 to 3 loop
                r(row, col) := s(row, (col + row) mod 4);
            end loop;
        end loop;

        -- Repack into block (big-endian)
        for col in 0 to 3 loop
            for row in 0 to 3 loop
                result(127 - 32*col - 8*row downto 120 - 32*col - 8*row) := r(row, col);
            end loop;
        end loop;

        return result;
    end function;

    ----------------------------------------------------------------------------
    -- xtime: Multiply by x (i.e., by 2) in GF(2^8)
    ----------------------------------------------------------------------------
    function xtime(b : byte_t) return byte_t is
        variable result : byte_t;
    begin
        result := b(6 downto 0) & '0';
        if b(7) = '1' then
            result := result xor x"1b";
        end if;
        return result;
    end function;

    ----------------------------------------------------------------------------
    -- MixColumn: Mix a single column (big-endian byte order)
    -- Matrix multiplication in GF(2^8):
    -- [2 3 1 1]   [s0]
    -- [1 2 3 1] * [s1]
    -- [1 1 2 3]   [s2]
    -- [3 1 1 2]   [s3]
    ----------------------------------------------------------------------------
    function mix_column(col : word_t) return word_t is
        variable s0, s1, s2, s3 : byte_t;
        variable r0, r1, r2, r3 : byte_t;
        variable t0, t1, t2, t3 : byte_t;  -- 2*s_i
    begin
        -- Big-endian: byte 0 is at MSB
        s0 := col(31 downto 24);
        s1 := col(23 downto 16);
        s2 := col(15 downto 8);
        s3 := col(7 downto 0);

        t0 := xtime(s0);
        t1 := xtime(s1);
        t2 := xtime(s2);
        t3 := xtime(s3);

        -- 3*x = 2*x xor x
        r0 := t0 xor (t1 xor s1) xor s2 xor s3;
        r1 := s0 xor t1 xor (t2 xor s2) xor s3;
        r2 := s0 xor s1 xor t2 xor (t3 xor s3);
        r3 := (t0 xor s0) xor s1 xor s2 xor t3;

        return r0 & r1 & r2 & r3;
    end function;

    ----------------------------------------------------------------------------
    -- MixColumns: Apply mix_column to all 4 columns (big-endian)
    ----------------------------------------------------------------------------
    function mix_columns(state : block_t) return block_t is
        variable result : block_t;
    begin
        -- Column 0 is bits 127:96, column 3 is bits 31:0
        for i in 0 to 3 loop
            result(127 - 32*i downto 96 - 32*i) := mix_column(state(127 - 32*i downto 96 - 32*i));
        end loop;
        return result;
    end function;

    ----------------------------------------------------------------------------
    -- AddRoundKey: XOR state with round key
    ----------------------------------------------------------------------------
    function add_round_key(state : block_t; key : block_t) return block_t is
    begin
        return state xor key;
    end function;

    ----------------------------------------------------------------------------
    -- SubWord: Apply S-box to each byte of a word (big-endian)
    ----------------------------------------------------------------------------
    function sub_word(w : word_t) return word_t is
        variable result : word_t;
    begin
        -- Byte 0 at MSB (bits 31:24), byte 3 at LSB (bits 7:0)
        for i in 0 to 3 loop
            result(31 - 8*i downto 24 - 8*i) := sub_byte(w(31 - 8*i downto 24 - 8*i));
        end loop;
        return result;
    end function;

    ----------------------------------------------------------------------------
    -- RotWord: Rotate word left by one byte (for key expansion)
    -- [a0 a1 a2 a3] -> [a1 a2 a3 a0]
    ----------------------------------------------------------------------------
    function rot_word(w : word_t) return word_t is
    begin
        return w(23 downto 0) & w(31 downto 24);
    end function;

    ----------------------------------------------------------------------------
    -- Key Expansion: Generate all 11 round keys from 128-bit cipher key
    ----------------------------------------------------------------------------
    function key_expansion(key : block_t) return key_schedule_t is
        variable w : key_schedule_t;
        variable temp : word_t;
        type word_array is array (0 to 43) of word_t;
        variable words : word_array;
    begin
        -- First 4 words are the original key (big-endian)
        -- Word 0 is bits 127:96, word 3 is bits 31:0
        for i in 0 to 3 loop
            words(i) := key(127 - 32*i downto 96 - 32*i);
        end loop;

        -- Generate remaining words
        for i in 4 to 43 loop
            temp := words(i-1);
            if (i mod 4) = 0 then
                -- Rcon: byte 0 is the round constant, bytes 1-3 are zero
                -- Big-endian: Rcon goes in MSB position
                temp := sub_word(rot_word(temp)) xor (RCON(i/4) & x"000000");
            end if;
            words(i) := words(i-4) xor temp;
        end loop;

        -- Pack words into round keys (big-endian)
        for r in 0 to 10 loop
            w(r) := words(4*r) & words(4*r+1) & words(4*r+2) & words(4*r+3);
        end loop;

        return w;
    end function;

    ----------------------------------------------------------------------------
    -- AES Round: Perform one round of AES
    -- Final round skips MixColumns
    ----------------------------------------------------------------------------
    function aes_round(state : block_t; round_key : block_t; is_final : boolean) return block_t is
        variable temp : block_t;
    begin
        temp := sub_bytes(state);
        temp := shift_rows(temp);
        if not is_final then
            temp := mix_columns(temp);
        end if;
        temp := add_round_key(temp, round_key);
        return temp;
    end function;

end package body aes_pkg;
