# Copyright is waived. No warranty is provided. Unrestricted use and modification is permitted.

import os
import io
import struct


class Stream:
    """
    Virtual base class for ByteStream, FileStream and SocketStream
    """

    LITTLE_ENDIAN = 0
    BIG_ENDIAN = 1

    def __init__(self, endian=None):
        self.position = 0
        self.length = 0
        self.endian = endian if endian else self.LITTLE_ENDIAN
        self.endian_stack = []
        self.position_stack = []

    def reset(self):
        self.position = 0
        self.length = 0
        self.endian_stack = []
        self.position_stack = []

    def get_length(self):
        return self.length

    def set_endian(self, value):
        self.endian = value

    def get_endian(self):
        return self.endian

    def push_endian(self, new_value=None):
        self.endian_stack.append(self.endian)
        if new_value is not None:
            self.endian = new_value

    def pop_endian(self):
        self.endian = self.endian_stack.pop()

    def set_position(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            new_position = offset
        elif whence == io.SEEK_CUR:
            new_position = self.position + offset
        elif whence == io.SEEK_END:
            new_position = self.length + offset
        else:
            raise ValueError("Invalid position basis")
        if new_position < 0 or new_position > self.length:
            raise ValueError("Position out of range")
        self.position = new_position

    def get_position(self):
        return self.position

    def push_position(self, new_position):
        current_position = self.position
        self.position_stack.append(current_position)
        self.position = new_position
        return current_position

    def pop_position(self):
        self.position = self.position_stack.pop()

    def is_eof(self):
        return self.position == self.length

    def write_u8(self, value):
        raise "Virtual function"

    def write_u8_array(self, data):
        raise "Virtual function"

    def write_bool(self, value):
        self.write_u8(1 if value else 0)

    def write_u16(self, value):
        if self.endian == self.LITTLE_ENDIAN:
            self.write_u8(value & 0xff)
            self.write_u8(value >> 8)
        else:
            self.write_u8(value >> 8)
            self.write_u8(value & 0xff)

    def write_u24(self, value):
        if self.endian == self.LITTLE_ENDIAN:
            self.write_u8(value & 0xff)
            self.write_u8((value >> 8) & 0xff)
            self.write_u8(value >> 16)
        else:
            self.write_u8(value >> 16)
            self.write_u8((value >> 8) & 0xff)
            self.write_u8(value & 0xff)

    def write_u32(self, value):
        if self.endian == self.LITTLE_ENDIAN:
            self.write_u16(value & 0xffff)
            self.write_u16(value >> 16)
        else:
            self.write_u16(value >> 16)
            self.write_u16(value & 0xffff)

    def write_u64(self, value):
        if self.endian == self.LITTLE_ENDIAN:
            self.write_u32(value & 0xffffffff)
            self.write_u32(value >> 32)
        else:
            self.write_u32(value >> 32)
            self.write_u32(value & 0xffffffff)

    def write_f32(self, value):
        if self.endian == self.LITTLE_ENDIAN:
            value = struct.pack('<f', value)
        else:
            value = struct.pack('>f', value)
        self.write_u8_array(value)

    def write_f64(self, value):
        if self.endian == self.LITTLE_ENDIAN:
            value = struct.pack('<d', value)
        else:
            value = struct.pack('>d', value)
        self.write_u8_array(value)

    # variable length unsigned quantity
    # value is stored 7 bits at a time in little-endian order; last value has MSB of 0
    def write_vluq(self, value):
        while value > 0x7f:
            self.write_u8((value & 0x7f) + 0x80)
            value >>= 7
        self.write_u8(value)

    # variable length signed quantity; same as VLUQ but the sign is stored in the low bit
    def write_vlsq(self, value):
        sign = 1 if value < 0 else 0
        value = (abs(value) << 1) + sign
        self.write_vluq(value)

    def write_string(self, string):
        string_data = string.encode("latin_1")
        self.write_u8_array(string_data)

    # null terminated string
    def write_nt_string(self, string):
        self.write_string(string)
        self.write_u8(0)

    # string preceded by length as a variable-length-unsigned-quantity
    def write_vluq_string(self, string):
        string_data = string.encode("latin_1")
        self.write_vluq(len(string_data))
        self.write_u8_array(string_data)

    def write_name_list(self, names):
        string = ",".join(names)
        self.write_u32(len(string))
        self.write_string(string)

    def read_u8(self):
        raise "Virtual function"

    def read_u8_array(self, length):
        raise "Virtual function"

    def read_bool(self):
        value = self.read_u8()
        return False if value == 0 else True

    def read_u16(self):
        if self.endian == self.LITTLE_ENDIAN:
            value = self.read_u8() + (self.read_u8() << 8)
        else:
            value = (self.read_u8() << 8) + self.read_u8()
        return value

    def read_u24(self):
        if self.endian == self.LITTLE_ENDIAN:
            value = self.read_u8() + (self.read_u8() << 8) + (self.read_u8() << 16)
        else:
            value = (self.read_u8() << 16) + (self.read_u8() << 8) + self.read_u8()
        return value

    def read_u32(self):
        if self.endian == self.LITTLE_ENDIAN:
            value = self.read_u16() + (self.read_u16() << 16)
        else:
            value = (self.read_u16() << 16) + self.read_u16()
        return value

    def read_u64(self):
        if self.endian == self.LITTLE_ENDIAN:
            value = self.read_u32() + (self.read_u32() << 32)
        else:
            value = (self.read_u32() << 32) + self.read_u32()
        return value

    def read_f32(self):
        data = self.read_u8_array(4)
        if self.endian == self.LITTLE_ENDIAN:
            return struct.unpack('<f', data)[0]
        else:
            return struct.unpack('>f', data)[0]

    def read_f64(self):
        data = self.read_u8_array(8)
        if self.endian == self.LITTLE_ENDIAN:
            return struct.unpack('<d', data)[0]
        else:
            return struct.unpack('>d', data)[0]

    def read_vluq(self):
        accumulator = shift = 0
        value = self.read_u8()
        while value > 0x7f:
            accumulator += (value & 0x7f) << shift
            shift += 7
            value = self.read_u8()
        return accumulator + (value << shift)

    def read_vlsq(self):
        value = self.read_vluq()
        sign = value & 1
        value >>= 1
        return -value if sign else value

    def read_string(self, length):
        value = self.read_u8_array(length)
        return value.decode("latin_1")

    # null terminated string; null character is not returned with string
    def read_nt_string(self):
        output = bytearray()
        value = self.read_u8()
        while value != 0:
            output.append(value)
            value = self.read_u8()
        return output.decode("latin_1")

    # CR/LF terminated string; CR/LF is returned with string
    def read_crlf_string(self):
        output = bytearray()
        value = self.read_u8()
        while value != 0x0d:
            output.append(value)
            value = self.read_u8()
        output.append(value)
        output.append(self.read_u8())      # Expected to be 0x0a (line feed)
        return output.decode("latin_1")

    # string preceded by length as a variable-length-unsigned-quantity
    def read_vluq_string(self):
        length = self.read_vluq()
        return self.read_string(length)

    def read_utf16_string(self, num_chars):
        value = self.read_u8_array(num_chars*2)
        return value.decode("utf-16")

    def read_nt_utf16_string(self):
        output = bytearray()
        value = self.read_utf16_string(1)
        while value != 0:
            output.append(value)
            value = self.read_utf16_string(1)
        return output

    def read_name_list(self):
        string_length = self.read_u32()
        names = self.read_string(string_length)
        return names.split(",")


class ByteStream(Stream):

    def __init__(self, endian=None):
        Stream.__init__(self, endian)
        self.data = bytearray()

    def reset(self):
        Stream.reset(self)
        self.data = bytearray()

    def set_data(self, data, length=None):
        self.position = 0
        self.data = bytearray(data)
        self.length = length if length else len(self.data)

    def get_data(self):
        return self.data

    def write_u8(self, value):
        # For now, ignores position and always writes to end of byte array
        self.data.append(value)
        self.length += 1
        self.position += 1

    def write_u8_array(self, data):
        # For now, ignores position and always writes to end of byte array
        self.data += data
        self.length += len(data)
        self.position += len(data)

    def read_u8(self):
        value = self.data[self.position]
        self.position += 1
        return value

    def read_u8_array(self, length):
        value = self.data[self.position:self.position + length]
        self.position += length
        return value


class FileStream(Stream):

    def __init__(self, file_name, mode, endian=None):
        Stream.__init__(self, endian)
        self.handle = io.open(file_name, mode)
        self.length = os.path.getsize(file_name)

    def close(self):
        self.handle.close()

    def set_position(self, offset, whence=io.SEEK_SET):
        Stream.set_position(self, offset, whence)
        self.handle.seek(offset, whence)

    def get_position(self):
        self.position = self.handle.tell()
        return self.position

    def get_remaining(self):
        return self.length - self.handle.tell()

    def is_eof(self):
        return self.handle.tell() == self.length

    def write_u8(self, value):
        self.handle.write(value)
        self.length += 1
        self.position += 1

    def write_u8_array(self, data):
        self.handle.write(data)
        self.length += len(data)
        self.position += len(data)

    def read_u8(self):
        return ord(self.handle.read(1))

    def read_u8_array(self, length):
        return bytearray(self.handle.read(length))

    def flush(self):
        self.handle.flush()


class SocketStream(Stream):

    def __init__(self, socket, endian=None):
        Stream.__init__(self, endian)
        self.socket = socket
        self.write_buffer = bytearray()
        self.read_buffer = bytearray()
        self.read_buffer_length = 0

    def close(self):
        self.socket.close()

    def set_position(self, offset, whence=io.SEEK_CUR):
        if whence == io.SEEK_SET:
            new_position = offset
        elif whence == io.SEEK_CUR:
            new_position = self.position + offset
        else:
            raise ValueError("Invalid position basis")
        if new_position < 0:
            raise ValueError("Position out of range")
        self.position = new_position

    def read_u8(self):
        return self.read_u8_array(1)[0]

    def read_u8_array(self, length):
        # Read data from socket; wait until enough data is available to satisfy request
        while self.position + length > len(self.read_buffer):
            bytes_needed = self.position + length - len(self.read_buffer)
            self.read_buffer += self.socket.recv(bytes_needed)
        data = self.read_buffer[self.position:self.position + length]
        self.position += length
        return data

    def write_u8(self, value):
        self.write_buffer.append(value)
        self.length += 1

    def write_u8_array(self, data):
        self.write_buffer += data
        self.length += len(data)

    def get_write_buffer(self):
        return self.write_buffer

    def flush(self):
        self.socket.sendall(self.write_buffer)
        self.write_buffer = bytearray()
        self.length = 0
