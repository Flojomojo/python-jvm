#/usr/bin/env python3
from io import BytesIO
from typing import BinaryIO
import pprint
from enum import Enum

# https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html


CONSTANT_TYPE_LOOKUP = {7: "Class", 9: "Fieldref", 10: "Methodref", 11: "InterfaceMethodref",
                        8: "String", 3: "Integer", 4: "Float", 5: "Long", 6: "Double", 12: "NameAndType",
                        1: "Utf8", 15: "MethodHandle", 16: "MethodType", 18: "InvokeDynamic"}

CLASS_ACCESS_FLAG_LOOKUP = {0x0001: "PUBLIC", 0x0010: "FINAL", 0x0020: "SUPER", 0x0200: "INTERFACE", 0x0400: "ABSTRACT", 
                      0x1000: "SYNTHETIC", 0x2000: "ANNOTATION", 0x4000: "ENUM"}

FIELD_ACCESS_FLAG_LOOKUP = {0x0001: "PUBLIC", 0x0002: "PRIVATE", 0x0004: "PROTECTED", 0x0008: "STATIC", 0x0010: "FINAL", 
                           0x0040: "VOLATILE", 0x0080: "TRANSIENT", 0x1000: "SYNTHETIC", 0x4000: "ENUM"}

METHOD_ACCESS_FLAG_LOOKUP = {0x0001: "PUBLIC", 0x0002: "PRIVATE", 0x0004: "PROTECTED", 0x0008: "STATIC", 0x0010: "FINAL",
                             0x0020: "SYNCHRONIZED", 0x0040: "BRIDGE", 0x0080: "VARARGS", 0x0100: "NATIVE", 0x0400: "ABSTRACT",
                             0x0800: "STRICT", 0x1000: "SYNTHETIC"}

class Opcode(Enum):
    getstatic = 0xb2
    ldc = 0x12
    invokevirtual = 0xb6
    invokestatic = 0xb8
    iconst_m1 = 0x2
    iconst_0 = 0x3
    iconst_1 = 0x4
    iconst_2 = 0x5
    iconst_3 = 0x6
    iconst_4 = 0x7
    iconst_5 = 0x8
    ret = 0xb1
    istore_0 = 0x3b
    istore_1 = 0x3c
    istore_2 = 0x3d
    istore_3 = 0x3e
    iload_0 = 0x1a
    iload_1 = 0x1b
    iload_2 = 0x1c
    iload_3 = 0x3e
    bipush = 0x10
    sipush = 0x11

    @staticmethod
    def get_by_value(hex_num: int):
        for op in Opcode:
            print(op.value, hex_num)
            if op.value == hex_num:
                return op
        raise NotImplementedError("Opcode not implemented")

class JvmStackElement:
    def __init__(self):
        pass

class JvmPrintStreamElement(JvmStackElement):
    def __init__(self):
        pass

class JvmIntegerElement(JvmStackElement):
    def __init__(self, value: int):
        self.val = value

class JvmConstantElement(JvmStackElement):
    def __init__(self, const: any):
        self.const = const

    def get_bytes_value(self, parsed_class: dict):
        if self.const["tag"] == "String":
            return get_value_from_constant_pool(parsed_class, self.const["string_index"])["bytes"]
        if self.const["tag"] == "Integer":
            return self.const["bytes"]

class JvmStoreElement(JvmStackElement):
    def __init__(self, index: int):
        self.index = index

class JvmLoadElement(JvmStackElement):
    def __init__(self, index: int):
        self.index = index

def get_access_flag(flag: str, flag_lookup: dict):
    return [name for value, name in flag_lookup.items() if value&int(flag, 16) != 0]

def get_code_of_method(parsed_class: dict, method: dict):
    return get_attributes_by_name(parsed_class, method["attribute_info"], "Code")

def get_method_by_name(parsed_class: dict, name: str) -> list[dict]:
    return [method for _, method in parsed_class["methods"].items()
            if parsed_class["constant_pool"][method["name_index"] - 1]["bytes"] == name]

def get_attributes_by_name(parsed_class: dict, attributes: dict, name: str):
    return [attribute for _, attribute in attributes.items()
            if parsed_class["constant_pool"][attribute["attribute_name_index"] - 1]["bytes"] == name]

def get_value_from_constant_pool(parsed_class: dict, index: int) -> any:
    return parsed_class["constant_pool"][index - 1]

def get_name_from_parsed_class(parsed_class: dict, index: int) -> str:
    name_index = get_value_from_constant_pool(parsed_class, index)["name_index"]
    return get_value_from_constant_pool(parsed_class, name_index)["bytes"]


pp = pprint.PrettyPrinter(indent=2)
def prettyprint(dict_var: dict) -> None:
    for item, value in dict_var.items():
        print(f"{item}: ", end="")
        pp.pprint(value)

def read_as(file: BinaryIO, byte_length: int, format: str) -> int | str:
    read_int = int.from_bytes(file.read(byte_length), "big")
    if format == "int":
        return read_int
    elif format == "hex":
        return hex(read_int)
    return -1

def parse_constant(const_type: str, file: BinaryIO) -> dict:
    parsed_constant = {}
    match const_type:
        case "Methodref" | "Fieldref" | "InterfaceMethodref":
            parsed_constant["class_index"] = read_as(file, 2, "int")
            parsed_constant["name_and_type_index"] = read_as(file, 2, "int")
        case "String":
            parsed_constant["string_index"] = read_as(file, 2, "int")
        case "Integer" | "Float":
            parsed_constant["bytes"] = read_as(file, 4, "int")
        case "Long" | "Double":
            parsed_constant["high_bytes"] = read_as(file, 4, "hex")
            parsed_constant["low_bytes"] = read_as(file, 4, "hex")
        case "NameAndType":
            parsed_constant["name_index"] = read_as(file, 2, "int")
            parsed_constant["descriptor_index"] = read_as(file, 2, "int")
        case "Utf8":
            length = read_as(file, 2, "int")
            parsed_constant["length"] = length
            parsed_constant["bytes"] = file.read(length).decode("utf-8")
        case "MethodHandle":
            parsed_constant["reference_kind"] = read_as(file, 1, "int")
            parsed_constant["reference_index"] = read_as(file, 2, "int")
        case "MethodType":
            parsed_constant["descriptor_index"] = read_as(file, 2, "int")
        case "InvokeDynamic":
            parsed_constant["bootstrap_method_attr_index"] = read_as(file, 2, "int")
            parsed_constant["name_and_type_index"] = read_as(file, 2, "int")
        case "Class":
            parsed_constant["name_index"] = read_as(file, 2, "int")
        case _:
            print("Invalid const type: ", const_type)
    return parsed_constant

def parse_attributes(f: BinaryIO, count: int):
    parsed_attributes = {}
    for attribute_index in range(count):
        parsed_attribute = {}
        parsed_attribute["attribute_name_index"] = read_as(f, 2, "int")
        attribute_length = read_as(f, 4, "int")
        parsed_attribute["info"] = f.read(attribute_length)
        #parsed_attribute["info"] = hex(int(read_as(f, attribute_length, "int")))
        parsed_attributes[attribute_index] = parsed_attribute
    return parsed_attributes

filename = "Example.class"
def parse_class(filename: str) -> dict:
    parsed_class = {}
    with open(filename, "rb") as f:
        parsed_class["magic"] = read_as(f, 4, "hex") 
        parsed_class["minor_version"] = read_as(f, 2, "int")
        parsed_class["major_version"] = read_as(f, 2, "int")
        constant_pool_count = read_as(f, 2, "int")
        parsed_constant_pool = {}
        for constant in range(constant_pool_count - 1):
            current_tag = read_as(f, 1, "int")
            current_constant_type = CONSTANT_TYPE_LOOKUP[current_tag]
            parsed_constant = parse_constant(current_constant_type, f)
            if parsed_constant == {}:
                break
            parsed_constant["tag"] = current_constant_type
            parsed_constant_pool[constant] = parsed_constant
        parsed_class["constant_pool"] = parsed_constant_pool
        parsed_class["access_flag"] = get_access_flag(read_as(f, 2, "hex"), CLASS_ACCESS_FLAG_LOOKUP)
        parsed_class["this_class"] = read_as(f, 2, "int")
        parsed_class["super_class"] = read_as(f, 2, "int")
        interfaces_count = read_as(f, 2, "int")
        parsed_class["interfaces"] = read_as(f, interfaces_count, "hex")
        fields_count = read_as(f, 2, "int")
        parsed_fields = {}
        for field_index in range(fields_count):
            parsed_field = {}
            parsed_field["access_flag"] = get_access_flag(read_as(f, 2, "hex"), FIELD_ACCESS_FLAG_LOOKUP)
            parsed_field["name_index"] = read_as(f, 2, "int")
            parsed_field["descriptor_index"] = read_as(f, 2, "int")
            attributes_count = read_as(f, 2, "int")
            parsed_attributes = parse_attributes(f, attributes_count)
            parsed_field["attribute_info"] = parsed_attributes
            parsed_fields[field_index] = parsed_field
        parsed_class["fields"] = parsed_fields
        methods_count = read_as(f, 2, "int")
        parsed_methods = {}
        for method_index in range(methods_count):
            parsed_method = {}
            parsed_method["access_flag"] = get_access_flag(read_as(f, 2, "hex"), METHOD_ACCESS_FLAG_LOOKUP)
            parsed_method["name_index"] = read_as(f, 2, "int")
            parsed_method["descriptor_index"] = read_as(f, 2, "int")
            attributes_count = read_as(f, 2, "int")
            parsed_attributes = parse_attributes(f, attributes_count)
            parsed_method["attribute_info"] = parsed_attributes
            parsed_methods[method_index] = parsed_method
        parsed_class["methods"] = parsed_methods
        attributes_count = read_as(f, 2, "int")
        parsed_class["attributes"] = parse_attributes(f, attributes_count)
    return parsed_class

def parse_code(code: bytes):
    parsed_code = {}
    with BytesIO(code) as f:
        parsed_code["max_stack"] = read_as(f, 2, "int")
        parsed_code["max_locals"] = read_as(f, 2, "int")
        code_length = read_as(f, 4, "int")
        parsed_code["code"] = f.read(code_length)
        exception_table_length = read_as(f, 2, "int")
        parsed_code["exception_table"] = read_as(f, exception_table_length, "hex")
    return parsed_code

def exec_code(parsed_class: dict, code: bytes):
    jvm_stack = []
    with BytesIO(code) as f:
        while f.tell() < len(code):
            unparsed_opcode = int(read_as(f, 1, "int"))
            try:
                opcode = Opcode(unparsed_opcode)
            except:
                raise NotImplementedError(f"Invalid opcode {hex(unparsed_opcode)}")
            match opcode:
                case Opcode.getstatic:
                    index = read_as(f, 2, "int")
                    fieldref = get_value_from_constant_pool(parsed_class, index)
                    class_name = get_name_from_parsed_class(parsed_class, fieldref["class_index"])
                    member_name = get_name_from_parsed_class(parsed_class, fieldref["name_and_type_index"])
                    # TODO implement parsing of system class
                    if class_name == "java/lang/System" and member_name == "out":
                        jvm_stack.append(JvmPrintStreamElement())
                    else: 
                        raise NotImplementedError(f"Member {class_name}/{member_name} not implemented")
                case Opcode.sipush:
                    bytes = read_as(f, 2, "int")
                    jvm_stack.append(JvmIntegerElement(bytes))
                case Opcode.bipush:
                    byte = read_as(f, 1, "int")
                    jvm_stack.append(JvmIntegerElement(byte))
                case Opcode.ldc:
                    index = read_as(f, 1, "int")
                    jvm_stack.append(JvmConstantElement(get_value_from_constant_pool(parsed_class, index)))
                case Opcode.iconst_m1 | Opcode.iconst_0 | Opcode.iconst_1 | Opcode.iconst_2 | Opcode.iconst_3 | Opcode.iconst_4 | Opcode.iconst_5:
                    jvm_stack.append(JvmIntegerElement(opcode.value-3))
                case Opcode.istore_0 | Opcode.istore_1 | Opcode.istore_2 | Opcode.istore_3:
                    jvm_stack.append(JvmStoreElement(opcode.value - 59))
                case Opcode.iload_0 | Opcode.iload_1 | Opcode.iload_2 | Opcode.iload_3:
                    jvm_stack.append(JvmLoadElement(opcode.value - 26))
                case Opcode.invokevirtual:
                    index = read_as(f, 2, "int")
                    methodref = get_value_from_constant_pool(parsed_class, index)
                    class_name = get_name_from_parsed_class(parsed_class, methodref["class_index"])
                    member_name = get_name_from_parsed_class(parsed_class, methodref["name_and_type_index"])
                    if class_name != "java/io/PrintStream" or member_name != "println":
                        raise NotImplementedError(f"Member {class_name}.{member_name} not implemented")
                    if len(jvm_stack) < 2:
                        raise RuntimeError(f"Member {class_name}.{member_name} expected 2 arguments, not {len(jvm_stack)}") 
                    execute_jvm_stack(jvm_stack)
                case Opcode.invokestatic:
                    index = read_as(f, 2, "int") 
                    methodref = get_value_from_constant_pool(parsed_class, index)
                    method_name = get_name_from_parsed_class(parsed_class, methodref["name_and_type_index"])
                    exec_method(parsed_class, method_name)
                case Opcode.ret:
                    return
                case other:
                    raise NotImplementedError(f"Unimplemented opcode: {opcode}")

def execute_jvm_stack(jvm_stack: list):
    local_var_stack = [-1, -1, -1, -1]
    val = None 
    act = None
    while len(jvm_stack) > 0:
        current_stack_element = jvm_stack.pop(0)
        match current_stack_element:
            case JvmLoadElement():
                index = current_stack_element.index
                val = local_var_stack[index]
            case JvmStoreElement():
                index = current_stack_element.index
                local_var_stack[index] = val
                val = None
            case JvmConstantElement():
                val = current_stack_element.get_bytes_value(parsed_class)
            case JvmPrintStreamElement():
                act = print
            case JvmIntegerElement():
                val = current_stack_element.val
            case other:
                raise NotImplementedError(f"Stack element {type(current_stack_element)}")
        if val != None and act != None:
            act(f"java: {val}")
            act = None
            val = None

def exec_method(parsed_class: dict, method_name: str):
    method = get_method_by_name(parsed_class, method_name)
    assert len(method) == 1, f"Could not find method {method_name}"
    [method] = method
    code = get_code_of_method(parsed_class, method)
    assert len(code) == 1, f"What?"
    [code] = code
    parsed_code = parse_code(code["info"])
    exec_code(parsed_class, parsed_code["code"])

parsed_class = parse_class(filename)
exec_method(parsed_class, "main")
