#if canImport(Darwin)
import Darwin.C
#elseif canImport(Glibc)
import Glibc
#elseif canImport(MSVCRT)
import MSVCRT
#endif

import PhoneNumberKit
import enum PhoneNumberKit.PhoneNumberError
import Foundation

let phoneNumberKit = PhoneNumberKit()

@_cdecl("LLVMFuzzerTestOneInput")
public func test(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    if (count <= 20) {
        return -1;
    }
    let fdp = FuzzedDataProvider(start, count)
    let num: Int8 = fdp.ConsumeIntegral()
    let str = fdp.ConsumeRandomLengthString()
    do {
        let phoneNumber = try phoneNumberKit.parse(str)

        phoneNumberKit.format(phoneNumber, toType: .international)
    } catch let error as PhoneNumberError {
        return -1;
    } catch {
        exit(EXIT_FAILURE);
    }
    return 0;
}