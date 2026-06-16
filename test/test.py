# SPDX-License-Identifier: Apache-2.0
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge, Timer

CMD_LOAD_PLAINTEXT = 0b00
CMD_LOAD_KEY = 0b01
CMD_START = 0b10
CMD_NEXT_OUTPUT = 0b11
VALID = 1 << 2
RESULT_READY = 1 << 3
BUSY = 1 << 4
PLAINTEXT_READY = 1 << 5
KEY_READY = 1 << 6


async def settle():
    await Timer(1, unit="ns")


async def pulse_command(dut, command: int, data: int = 0):
    dut.ui_in.value = data
    dut.uio_in.value = VALID | command
    await RisingEdge(dut.clk)
    await settle()
    dut.uio_in.value = 0
    await RisingEdge(dut.clk)
    await settle()


async def reset_design(dut):
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)
    await settle()
    assert int(dut.uio_oe.value) == 0xF8


async def load_block(dut, command: int, value: bytes):
    assert len(value) == 16
    for byte in value:
        await pulse_command(dut, command, byte)


async def run_vector(dut, plaintext_hex: str, key_hex: str, expected_hex: str):
    await reset_design(dut)
    plaintext = bytes.fromhex(plaintext_hex)
    key = bytes.fromhex(key_hex)
    expected = bytes.fromhex(expected_hex)

    await load_block(dut, CMD_LOAD_PLAINTEXT, plaintext)
    assert int(dut.uio_out.value) & PLAINTEXT_READY

    await load_block(dut, CMD_LOAD_KEY, key)
    status = int(dut.uio_out.value)
    assert status & PLAINTEXT_READY
    assert status & KEY_READY

    await pulse_command(dut, CMD_START)

    saw_busy = False
    for _ in range(350):
        await RisingEdge(dut.clk)
        await settle()
        status = int(dut.uio_out.value)
        saw_busy |= bool(status & BUSY)
        if status & RESULT_READY:
            break
    else:
        raise AssertionError("AES result_ready timeout")

    assert saw_busy, "busy never asserted"

    actual = bytearray()
    for index in range(16):
        actual.append(int(dut.uo_out.value))
        if index != 15:
            await pulse_command(dut, CMD_NEXT_OUTPUT)

    assert bytes(actual) == expected, (
        f"ciphertext mismatch: expected {expected.hex()}, got {bytes(actual).hex()}"
    )

    # Acknowledge the final byte and verify result_ready clears.
    await pulse_command(dut, CMD_NEXT_OUTPUT)
    assert not (int(dut.uio_out.value) & RESULT_READY)


@cocotb.test()
async def test_aes128_known_answer_vectors(dut):
    clock = Clock(dut.clk, 20, unit="ns")
    cocotb.start_soon(clock.start())

    await run_vector(
        dut,
        plaintext_hex="00112233445566778899aabbccddeeff",
        key_hex="000102030405060708090a0b0c0d0e0f",
        expected_hex="69c4e0d86a7b0430d8cdb78070b4c55a",
    )

    await run_vector(
        dut,
        plaintext_hex="6bc1bee22e409f96e93d7e117393172a",
        key_hex="2b7e151628aed2a6abf7158809cf4f3c",
        expected_hex="3ad77bb40d7a3660a89ecaf32466ef97",
    )
