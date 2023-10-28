#/usr/bin/env python3
from typing import BinaryIO
import pprint

# https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html

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
        parsed_attribute["info"] = read_as(f, attribute_length, "hex")
        parsed_attributes[attribute_index] = parsed_attribute
    return parsed_attributes


CONSTANT_TYPE_LOOKUP = {7: "Class", 9: "Fieldref", 10: "Methodref", 11: "InterfaceMethodref",
                        8: "String", 3: "Integer", 4: "Float", 5: "Long", 6: "Double", 12: "NameAndType",
                        1: "Utf8", 15: "MethodHandle", 16: "MethodType", 18: "InvokeDynamic"}

filename = "Example.class"
def parse_class(filename: str) -> dict:
    parsed_class = {}
    with open(filename, "rb") as f:
        print(type(f))
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
        parsed_class["access_flag"] = read_as(f, 2, "int")
        parsed_class["this_class"] = read_as(f, 2, "int")
        parsed_class["super_class"] = read_as(f, 2, "int")
        interfaces_count = read_as(f, 2, "int")
        parsed_class["interfaces"] = read_as(f, interfaces_count, "hex")
        fields_count = read_as(f, 2, "int")
        parsed_fields = {}
        for field_index in range(fields_count):
            parsed_field = {}
            parsed_field["access_flag"] = read_as(f, 2, "int")
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
            parsed_method["access_flag"] = read_as(f, 2, "int")
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

parsed_class = parse_class(filename)
prettyprint(parsed_class)
for index, attribute in parsed_class["attributes"].items():
    print(parsed_class["constant_pool"][attribute["attribute_name_index"]])
