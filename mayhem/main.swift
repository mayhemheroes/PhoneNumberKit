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
import SwiftGlibc

let phoneNumberKit = PhoneNumberKit()

let supported_formats = [PhoneNumberFormat.international, PhoneNumberFormat.national, PhoneNumberFormat.e164]


@_cdecl("LLVMFuzzerTestOneInput")
public func test(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let fdp = FuzzedDataProvider(start, count)
    do {
        let phoneNumber = try phoneNumberKit.parse(
                fdp.ConsumeRandomLengthString(),
                withRegion: fdp.ConsumeRandomLengthString(),
                ignoreType: fdp.ConsumeBoolean()
        )

        let format = fdp.PickValueInList(from: supported_formats)
        let choice = fdp.ConsumeIntegralInRange(from: 0, to: 3)

        switch (choice) {
        case 0:
            phoneNumberKit.format(phoneNumber, toType: format, withPrefix: fdp.ConsumeBoolean())
        case 1:
            phoneNumberKit.isValidPhoneNumber(fdp.ConsumeRandomLengthString())
        case 2:
            phoneNumberKit.countries(withCode: fdp.ConsumeIntegral())
        case 3:
            phoneNumberKit.countryCode(for: fdp.ConsumeRandomLengthString())
        default:
            break
        }

    } catch let _ as PhoneNumberError {
        return -1;
    } catch {
        exit(EXIT_FAILURE);
    }
    return 0;
}