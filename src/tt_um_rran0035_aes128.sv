/*
 * Low-area AES-128 Tiny Tapeout wrapper for ECE4063 Group RR0035.
 *
 * Input protocol (uio_in[2] is a one-cycle valid strobe):
 *   uio_in[1:0] = 2'b00 : load one plaintext byte from ui_in, MSB first
 *   uio_in[1:0] = 2'b01 : load one key byte from ui_in, MSB first
 *   uio_in[1:0] = 2'b10 : start encryption after 16 plaintext and 16 key bytes
 *   uio_in[1:0] = 2'b11 : advance to the next ciphertext output byte
 *
 * Outputs:
 *   uo_out      : current ciphertext byte, MSB first
 *   uio_out[3]  : result_ready (sticky until the final byte is acknowledged)
 *   uio_out[4]  : AES core busy
 *   uio_out[5]  : 16 plaintext bytes loaded
 *   uio_out[6]  : 16 key bytes loaded
 *   uio_out[7]  : wrapper ready to accept a command
 */
`default_nettype none

module tt_um_rran0035_aes128 (
    input  wire [7:0] ui_in,
    output wire [7:0] uo_out,
    input  wire [7:0] uio_in,
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,
    input  wire       ena,
    input  wire       clk,
    input  wire       rst_n
);
    localparam [1:0] CMD_LOAD_PLAINTEXT = 2'b00;
    localparam [1:0] CMD_LOAD_KEY       = 2'b01;
    localparam [1:0] CMD_START          = 2'b10;
    localparam [1:0] CMD_NEXT_OUTPUT    = 2'b11;

    wire command_valid = uio_in[2];
    wire [1:0] command = uio_in[1:0];

    reg [127:0] plaintext_register;
    reg [127:0] key_register;
    reg [127:0] result_register;
    reg [4:0] plaintext_count;
    reg [4:0] key_count;
    reg [3:0] output_index;
    reg result_ready;
    reg core_start;

    wire core_busy;
    wire core_done;
    wire [127:0] core_ciphertext;

    aes_core_lowarea_tt aes_core (
        .clk(clk),
        .rst_n(rst_n),
        .start(core_start),
        .plaintext(plaintext_register),
        .key(key_register),
        .busy(core_busy),
        .done(core_done),
        .ciphertext(core_ciphertext)
    );

    reg [7:0] selected_output_byte;
    always @* begin
        case (output_index)
            4'd0:  selected_output_byte = result_register[127:120];
            4'd1:  selected_output_byte = result_register[119:112];
            4'd2:  selected_output_byte = result_register[111:104];
            4'd3:  selected_output_byte = result_register[103:96];
            4'd4:  selected_output_byte = result_register[95:88];
            4'd5:  selected_output_byte = result_register[87:80];
            4'd6:  selected_output_byte = result_register[79:72];
            4'd7:  selected_output_byte = result_register[71:64];
            4'd8:  selected_output_byte = result_register[63:56];
            4'd9:  selected_output_byte = result_register[55:48];
            4'd10: selected_output_byte = result_register[47:40];
            4'd11: selected_output_byte = result_register[39:32];
            4'd12: selected_output_byte = result_register[31:24];
            4'd13: selected_output_byte = result_register[23:16];
            4'd14: selected_output_byte = result_register[15:8];
            4'd15: selected_output_byte = result_register[7:0];
            default: selected_output_byte = 8'h00;
        endcase
    end

    assign uo_out = result_ready ? selected_output_byte : 8'h00;
    assign uio_out = {
        (ena && !core_busy),       // bit 7: wrapper ready
        (key_count == 5'd16),      // bit 6: key loaded
        (plaintext_count == 5'd16),// bit 5: plaintext loaded
        core_busy,                 // bit 4: AES busy
        result_ready,              // bit 3: result ready
        3'b000
    };
    assign uio_oe = 8'b1111_1000;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            plaintext_register <= 128'b0;
            key_register       <= 128'b0;
            result_register    <= 128'b0;
            plaintext_count    <= 5'd0;
            key_count          <= 5'd0;
            output_index       <= 4'd0;
            result_ready       <= 1'b0;
            core_start         <= 1'b0;
        end else begin
            core_start <= 1'b0;

            if (core_done) begin
                result_register <= core_ciphertext;
                output_index    <= 4'd0;
                result_ready    <= 1'b1;
            end

            if (ena && command_valid) begin
                case (command)
                    CMD_LOAD_PLAINTEXT: begin
                        if (!core_busy) begin
                            if (plaintext_count < 5'd16) begin
                                plaintext_register <= {plaintext_register[119:0], ui_in};
                                plaintext_count    <= plaintext_count + 5'd1;
                            end else begin
                                plaintext_register <= {120'b0, ui_in};
                                plaintext_count    <= 5'd1;
                            end
                        end
                    end

                    CMD_LOAD_KEY: begin
                        if (!core_busy) begin
                            if (key_count < 5'd16) begin
                                key_register <= {key_register[119:0], ui_in};
                                key_count    <= key_count + 5'd1;
                            end else begin
                                key_register <= {120'b0, ui_in};
                                key_count    <= 5'd1;
                            end
                        end
                    end

                    CMD_START: begin
                        if (!core_busy && plaintext_count == 5'd16 && key_count == 5'd16) begin
                            core_start      <= 1'b1;
                            plaintext_count <= 5'd0;
                            key_count       <= 5'd0;
                            output_index    <= 4'd0;
                            result_ready    <= 1'b0;
                        end
                    end

                    CMD_NEXT_OUTPUT: begin
                        if (result_ready) begin
                            if (output_index == 4'd15) begin
                                output_index <= 4'd0;
                                result_ready <= 1'b0;
                            end else begin
                                output_index <= output_index + 4'd1;
                            end
                        end
                    end

                    default: begin
                    end
                endcase
            end
        end
    end

    wire _unused = &{uio_in[7:3], 1'b0};
endmodule

`default_nettype wire
