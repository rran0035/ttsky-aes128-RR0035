// Low-area AES-128 encryption core for Tiny Tapeout.
// One shared S-box is time-multiplexed between state SubBytes (16 bytes)
// and key expansion SubWord (4 bytes). Encryption latency is 211 cycles.
module aes_core_lowarea_tt (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         start,
    input  logic [127:0] plaintext,
    input  logic [127:0] key,
    output logic         busy,
    output logic         done,
    output logic [127:0] ciphertext
);
    localparam logic [2:0] IDLE = 3'd0;
    localparam logic [2:0] SUB  = 3'd1;
    localparam logic [2:0] KEYP = 3'd2;
    localparam logic [2:0] COMB = 3'd3;
    localparam logic [2:0] FIN  = 3'd4;

    logic [2:0] state;
    logic [7:0] data_byte [0:15];
    logic [7:0] key_sub_byte [0:3];
    logic [127:0] round_key;
    logic [3:0] round_number;
    logic [4:0] byte_count;

    function automatic logic [7:0] xtime(input logic [7:0] value);
        begin
            xtime = value[7] ? ((value << 1) ^ 8'h1b) : (value << 1);
        end
    endfunction

    function automatic logic [31:0] mix_column(input logic [31:0] column);
        logic [7:0] s0, s1, s2, s3;
        begin
            s0 = column[31:24];
            s1 = column[23:16];
            s2 = column[15:8];
            s3 = column[7:0];
            mix_column[31:24] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
            mix_column[23:16] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
            mix_column[15:8]  = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
            mix_column[7:0]   = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
        end
    endfunction

    function automatic logic [127:0] mix_columns(input logic [127:0] value);
        begin
            mix_columns = {
                mix_column(value[127:96]),
                mix_column(value[95:64]),
                mix_column(value[63:32]),
                mix_column(value[31:0])
            };
        end
    endfunction

    function automatic logic [127:0] shift_rows(input logic [127:0] value);
        begin
            // State is stored column-major, byte 0 at value[127:120].
            shift_rows = {
                value[127:120], value[87:80],   value[47:40],   value[7:0],
                value[95:88],   value[55:48],   value[15:8],    value[103:96],
                value[63:56],   value[23:16],   value[111:104], value[71:64],
                value[31:24],   value[119:112], value[79:72],   value[39:32]
            };
        end
    endfunction

    function automatic logic [7:0] round_constant(input logic [3:0] round_value);
        begin
            case (round_value)
                4'd1:  round_constant = 8'h01;
                4'd2:  round_constant = 8'h02;
                4'd3:  round_constant = 8'h04;
                4'd4:  round_constant = 8'h08;
                4'd5:  round_constant = 8'h10;
                4'd6:  round_constant = 8'h20;
                4'd7:  round_constant = 8'h40;
                4'd8:  round_constant = 8'h80;
                4'd9:  round_constant = 8'h1b;
                4'd10: round_constant = 8'h36;
                default: round_constant = 8'h00;
            endcase
        end
    endfunction

    logic [7:0] rotated_key_byte [0:3];
    assign rotated_key_byte[0] = round_key[23:16];
    assign rotated_key_byte[1] = round_key[15:8];
    assign rotated_key_byte[2] = round_key[7:0];
    assign rotated_key_byte[3] = round_key[31:24];

    logic [7:0] sbox_input;
    logic [7:0] sbox_output;
    assign sbox_input = (state == KEYP)
                      ? rotated_key_byte[byte_count[1:0]]
                      : data_byte[byte_count[3:0]];

    aes_sbox_case shared_sbox (
        .a(sbox_input),
        .y(sbox_output)
    );

    logic [127:0] packed_state;
    logic [127:0] shifted_state;
    logic [127:0] mixed_state;
    logic [31:0] substituted_word;
    logic [31:0] key_schedule_temp;
    logic [31:0] next_word0, next_word1, next_word2, next_word3;
    logic [127:0] next_round_key;
    logic [127:0] next_state;

    assign packed_state = {
        data_byte[0],  data_byte[1],  data_byte[2],  data_byte[3],
        data_byte[4],  data_byte[5],  data_byte[6],  data_byte[7],
        data_byte[8],  data_byte[9],  data_byte[10], data_byte[11],
        data_byte[12], data_byte[13], data_byte[14], data_byte[15]
    };

    assign shifted_state = shift_rows(packed_state);
    assign mixed_state = (round_number == 4'd10)
                       ? shifted_state
                       : mix_columns(shifted_state);

    assign substituted_word = {
        key_sub_byte[0], key_sub_byte[1], key_sub_byte[2], key_sub_byte[3]
    };
    assign key_schedule_temp = substituted_word ^ {round_constant(round_number), 24'h000000};
    assign next_word0 = round_key[127:96] ^ key_schedule_temp;
    assign next_word1 = round_key[95:64]  ^ next_word0;
    assign next_word2 = round_key[63:32]  ^ next_word1;
    assign next_word3 = round_key[31:0]   ^ next_word2;
    assign next_round_key = {next_word0, next_word1, next_word2, next_word3};
    assign next_state = mixed_state ^ next_round_key;

    integer i;
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= IDLE;
            busy         <= 1'b0;
            done         <= 1'b0;
            ciphertext   <= 128'b0;
            round_key    <= 128'b0;
            round_number <= 4'b0;
            byte_count   <= 5'b0;
            for (i = 0; i < 16; i = i + 1)
                data_byte[i] <= 8'b0;
            for (i = 0; i < 4; i = i + 1)
                key_sub_byte[i] <= 8'b0;
        end else begin
            done <= 1'b0;
            case (state)
                IDLE: begin
                    if (start) begin
                        for (i = 0; i < 16; i = i + 1)
                            data_byte[i] <= plaintext[127-(8*i) -: 8] ^ key[127-(8*i) -: 8];
                        round_key    <= key;
                        round_number <= 4'd1;
                        byte_count   <= 5'd0;
                        busy         <= 1'b1;
                        state        <= SUB;
                    end
                end

                SUB: begin
                    data_byte[byte_count[3:0]] <= sbox_output;
                    if (byte_count == 5'd15) begin
                        byte_count <= 5'd0;
                        state      <= KEYP;
                    end else begin
                        byte_count <= byte_count + 5'd1;
                    end
                end

                KEYP: begin
                    key_sub_byte[byte_count[1:0]] <= sbox_output;
                    if (byte_count == 5'd3) begin
                        byte_count <= 5'd0;
                        state      <= COMB;
                    end else begin
                        byte_count <= byte_count + 5'd1;
                    end
                end

                COMB: begin
                    for (i = 0; i < 16; i = i + 1)
                        data_byte[i] <= next_state[127-(8*i) -: 8];
                    round_key <= next_round_key;
                    if (round_number == 4'd10) begin
                        state <= FIN;
                    end else begin
                        round_number <= round_number + 4'd1;
                        state        <= SUB;
                    end
                end

                FIN: begin
                    ciphertext <= packed_state;
                    busy       <= 1'b0;
                    done       <= 1'b1;
                    state      <= IDLE;
                end

                default: begin
                    state <= IDLE;
                    busy  <= 1'b0;
                end
            endcase
        end
    end
endmodule
