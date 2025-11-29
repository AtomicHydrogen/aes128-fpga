--------------------------------------------------------------------------------
-- AES-128 Controller with MicroBlaze I/O Bus Interface
-- 
-- Iterative design with pipelined key expansion
--
-- Register Map (32-bit aligned, accent via IO Bus):
--   0x00-0x0C : Key[127:0]        (4 words, write-only)
--   0x10-0x1C : Plaintext[127:0]  (4 words, write-only)
--   0x20-0x2C : Ciphertext[127:0] (4 words, read-only)
--   0x30      : Control/Status
--               Write: bit0=start, bit1=clear_done/irq, bit2=irq_enable
--               Read:  bit0=busy, bit1=done, bit2=irq_enable
--
-- Interrupt:
--   done_irq output is active-high when encryption completes and irq_enable=1
--   Connect to MicroBlaze external interrupt input
--   Clear by writing 1 to bit1 of control register
--
-- Timing: 17 clock cycles from start to done
--   - 5 cycles: key expansion (2 round keys per cycle)
--   - 1 cycle: initial AddRoundKey (ROUND_0)
--   - 9 cycles: rounds 1-9
--   - 1 cycle: round 10 (final)
--   - 1 cycle: output latching
--
-- IO Bus Timing:
--   - io_ready asserted 1 cycle after strobe
--   - io_read_data valid when io_ready is high
--------------------------------------------------------------------------------
library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

library work;
use work.aes_pkg.all;

entity controller is
    port (
        clk             : in  std_logic;
        rst             : in  std_logic;
        -- MicroBlaze I/O Bus
        io_addr         : in  std_logic_vector(31 downto 0);
        io_write_data   : in  std_logic_vector(31 downto 0);
        io_read_data    : out std_logic_vector(31 downto 0);
        io_addr_strobe  : in  std_logic;
        io_write_strobe : in  std_logic;
        io_read_strobe  : in  std_logic;
        io_ready        : out std_logic;
        -- Interrupt output (directly to MicroBlaze external interrupt)
        done_irq        : out std_logic
    );
end entity controller;

architecture rtl of controller is

    -- State machine
    type state_t is (IDLE, KEY_EXP_0, KEY_EXP_1, KEY_EXP_2, KEY_EXP_3, KEY_EXP_4,
                     ROUND_0, ROUNDS_1_9, ROUND_10, DONE);
    signal state : state_t;

    -- Round counter
    signal round_cnt : unsigned(3 downto 0);

    -- Data registers (active write targets)
    signal key_reg       : block_t;
    signal plaintext_reg : block_t;
    
    -- Latched registers (used during computation)
    signal key_latched       : block_t;
    signal plaintext_latched : block_t;
    
    -- AES state
    signal cipher_state : block_t;
    signal ciphertext   : block_t;

    -- Key schedule (built incrementally during KEY_EXP states)
    signal round_keys : key_schedule_t;

    -- Control signals
    signal start_pulse : std_logic;
    signal busy        : std_logic;
    signal done_flag   : std_logic;
    signal irq_enable  : std_logic;
    signal irq_clear   : std_logic;

    -- Address decoding
    signal addr_word : unsigned(5 downto 0);  -- Word-aligned address (bits 7:2)
    
    -- Helper function: expand one round key from previous round key
    -- prev_key = round_keys(n-1), returns round_keys(n)
    function expand_round_key(prev_key : block_t; rcon_idx : integer) return block_t is
        variable w_prev_last : std_logic_vector(31 downto 0);
        variable temp        : std_logic_vector(31 downto 0);
        variable result      : block_t;
    begin
        -- prev_key layout: [127:96]=w0, [95:64]=w1, [63:32]=w2, [31:0]=w3
        w_prev_last := prev_key(31 downto 0);  -- w[i-1] (last word of previous key)
        
        -- w[i] = SubWord(RotWord(w[i-1])) XOR Rcon XOR w[i-4]
        -- RCON is 8 bits, need to pad to 32 bits (Rcon in MSB position)
        temp := sub_word(rot_word(w_prev_last)) xor (RCON(rcon_idx) & x"000000");
        result(127 downto 96) := temp xor prev_key(127 downto 96);
        
        -- w[i+1] = w[i] XOR w[i-3]
        result(95 downto 64) := result(127 downto 96) xor prev_key(95 downto 64);
        
        -- w[i+2] = w[i+1] XOR w[i-2]
        result(63 downto 32) := result(95 downto 64) xor prev_key(63 downto 32);
        
        -- w[i+3] = w[i+2] XOR w[i-1]
        result(31 downto 0) := result(63 downto 32) xor prev_key(31 downto 0);
        
        return result;
    end function;

begin

    -- Address decoding (use bits 7:2 for word address)
    addr_word <= unsigned(io_addr(7 downto 2));

    ---------------------------------------------------------------------------
    -- Register Write/Read Logic with IO Bus Handshake
    ---------------------------------------------------------------------------
    process(clk)
    begin
        if rising_edge(clk) then
            if rst = '1' then
                key_reg       <= (others => '0');
                plaintext_reg <= (others => '0');
                start_pulse   <= '0';
                irq_enable    <= '0';
                irq_clear     <= '0';
                io_read_data  <= (others => '0');
                io_ready      <= '0';
    
            else
                start_pulse <= '0';  -- Default: clear start pulse
                irq_clear   <= '0';  -- Default: clear irq_clear pulse
                
                -- io_ready defaults to '0', only asserted for one cycle after strobe
                io_ready <= '0';

                if io_addr_strobe = '1' then
                    if io_write_strobe = '1' then
                        io_ready <= '1';  -- Acknowledge write (1 cycle after strobe)
                        case to_integer(addr_word) is
                            -- Key registers (0x00, 0x04, 0x08, 0x0C)
                            when 0 =>
                                key_reg(127 downto 96) <= io_write_data;
                            when 1 =>
                                key_reg(95 downto 64) <= io_write_data;
                            when 2 =>
                                key_reg(63 downto 32) <= io_write_data;
                            when 3 =>
                                key_reg(31 downto 0) <= io_write_data;

                            -- Plaintext registers (0x10, 0x14, 0x18, 0x1C)
                            when 4 =>
                                plaintext_reg(127 downto 96) <= io_write_data;
                            when 5 =>
                                plaintext_reg(95 downto 64) <= io_write_data;
                            when 6 =>
                                plaintext_reg(63 downto 32) <= io_write_data;
                            when 7 =>
                                plaintext_reg(31 downto 0) <= io_write_data;

                            -- Control register (0x30)
                            when 12 =>
                                if io_write_data(0) = '1' and busy = '0' then
                                    start_pulse <= '1';
                                end if;
                                if io_write_data(1) = '1' then
                                    irq_clear <= '1';
                                end if;
                                irq_enable <= io_write_data(2);

                            when others =>
                                null;
                        end case;
                        
                    elsif io_read_strobe = '1' then
                        io_ready <= '1';  -- Acknowledge read (1 cycle after strobe)
                        case to_integer(addr_word) is
                            -- Ciphertext registers (0x20, 0x24, 0x28, 0x2C)
                            when 8 =>
                                io_read_data <= ciphertext(127 downto 96);
                            when 9 =>
                                io_read_data <= ciphertext(95 downto 64);
                            when 10 =>
                                io_read_data <= ciphertext(63 downto 32);
                            when 11 =>
                                io_read_data <= ciphertext(31 downto 0);

                            -- Status register (0x30)
                            when 12 =>
                                io_read_data <= (2 => irq_enable, 1 => done_flag, 0 => busy, others => '0');

                            when others =>
                                io_read_data <= (others => '0');
                        end case;
                    end if;
                end if;
            end if;
        end if;
    end process;

    ---------------------------------------------------------------------------
    -- AES State Machine with Pipelined Key Expansion
    ---------------------------------------------------------------------------
    process(clk)
        variable rk_temp : block_t;
    begin
        if rising_edge(clk) then
            if rst = '1' then
                state            <= IDLE;
                round_cnt        <= (others => '0');
                cipher_state     <= (others => '0');
                ciphertext       <= (others => '0');
                done_flag        <= '0';
                key_latched      <= (others => '0');
                plaintext_latched <= (others => '0');
                round_keys       <= (others => (others => '0'));
            else
                -- Handle interrupt clear
                if irq_clear = '1' then
                    done_flag <= '0';
                end if;

                case state is
                    when IDLE =>
                        if start_pulse = '1' then
                            -- Latch inputs for computation
                            key_latched       <= key_reg;
                            plaintext_latched <= plaintext_reg;
                            done_flag         <= '0';
                            -- Round key 0 is the original key
                            round_keys(0)     <= key_reg;
                            state             <= KEY_EXP_0;
                        end if;

                    -- Key Expansion: 5 cycles, 2 round keys per cycle
                    when KEY_EXP_0 =>
                        -- Compute round keys 1 and 2
                        rk_temp := expand_round_key(round_keys(0), 1);
                        round_keys(1) <= rk_temp;
                        round_keys(2) <= expand_round_key(rk_temp, 2);
                        state <= KEY_EXP_1;

                    when KEY_EXP_1 =>
                        -- Compute round keys 3 and 4
                        rk_temp := expand_round_key(round_keys(2), 3);
                        round_keys(3) <= rk_temp;
                        round_keys(4) <= expand_round_key(rk_temp, 4);
                        state <= KEY_EXP_2;

                    when KEY_EXP_2 =>
                        -- Compute round keys 5 and 6
                        rk_temp := expand_round_key(round_keys(4), 5);
                        round_keys(5) <= rk_temp;
                        round_keys(6) <= expand_round_key(rk_temp, 6);
                        state <= KEY_EXP_3;

                    when KEY_EXP_3 =>
                        -- Compute round keys 7 and 8
                        rk_temp := expand_round_key(round_keys(6), 7);
                        round_keys(7) <= rk_temp;
                        round_keys(8) <= expand_round_key(rk_temp, 8);
                        state <= KEY_EXP_4;

                    when KEY_EXP_4 =>
                        -- Compute round keys 9 and 10
                        rk_temp := expand_round_key(round_keys(8), 9);
                        round_keys(9) <= rk_temp;
                        round_keys(10) <= expand_round_key(rk_temp, 10);
                        state <= ROUND_0;

                    -- AES Encryption: 12 cycles
                    when ROUND_0 =>
                        -- Initial AddRoundKey
                        cipher_state <= add_round_key(plaintext_latched, round_keys(0));
                        round_cnt    <= to_unsigned(1, 4);
                        state        <= ROUNDS_1_9;

                    when ROUNDS_1_9 =>
                        -- Rounds 1-9: SubBytes, ShiftRows, MixColumns, AddRoundKey
                        cipher_state <= aes_round(cipher_state, round_keys(to_integer(round_cnt)), false);

                        if round_cnt = 9 then
                            state <= ROUND_10;
                        else
                            round_cnt <= round_cnt + 1;
                        end if;

                    when ROUND_10 =>
                        -- Final round: SubBytes, ShiftRows, AddRoundKey (no MixColumns)
                        cipher_state <= aes_round(cipher_state, round_keys(10), true);
                        state        <= DONE;

                    when DONE =>
                        ciphertext <= cipher_state;
                        done_flag  <= '1';
                        state      <= IDLE;

                end case;
            end if;
        end if;
    end process;

    -- Busy signal: high when not in IDLE
    busy <= '0' when state = IDLE else '1';

    -- Interrupt output: active high when done and interrupts enabled
    done_irq <= done_flag and irq_enable;

end architecture rtl;