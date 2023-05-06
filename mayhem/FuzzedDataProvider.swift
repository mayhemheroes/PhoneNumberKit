// Created by Bailey Capuano for Mayhem integration
import Foundation

class FuzzedDataProvider {
    private var data_src: Data

    init(_ data: UnsafeRawPointer, _ count: Int) {
        data_src = Data(bytes: data, count: count)
    }

    func RemainingBytes() -> Int {
        return data_src.count
    }

    private func CastToUInt64<T: FixedWidthInteger>(_ value: T) -> UInt64 {
        return UInt64(value.magnitude)
    }
    /**
     Consumes a number in the given range from the data source
     - Parameters:
       - min: Minimum value to consume
       - max: Maximum value to consume
     - Returns: A number in the range [min, max] or |min| if remaining bytes are empty
     */
    func ConsumeIntegralInRange<T: FixedWidthInteger>(from min: T, to max: T) -> T {
        // TODO: This is wonky
        if (min > max) {
            return min;
        }
        let range = CastToUInt64(max) - CastToUInt64(min)
        var result: UInt64 = 0
        var offset: UInt64 = 0

        while offset < MemoryLayout<T>.size * 8 && (range >> offset) > 0 && RemainingBytes() != 0 {
            let popped = data_src.popLast()!
            result = (result << 8) | UInt64(exactly: popped)!
            offset += 8
        }

        if (range != UInt64.max) {
            result = result % (range + 1)
        }
        return min + T(result)
    }

    func ConsumeIntegral<T: FixedWidthInteger>() -> T {
        return ConsumeIntegralInRange(from: T.min, to: T.max)
    }

    func ConsumeRandomLengthString() -> String {
        var result = "";
        var i = 0

        while i < RemainingBytes() {
            // Build character from uint8
            var next = Character(UnicodeScalar(data_src.popFirst()!))

            if (next == "\\" && RemainingBytes() != 0) {
                next = Character(UnicodeScalar(data_src.popFirst()!))
                if (next != "\\") {
                    break;
                }
            }
            result.append(next)
            i += 1
        }
        return result
    }

    func ConsumeRemainingString() -> String {
        let str = String(bytes: data_src, encoding: .utf8) ?? ""
        data_src.removeAll();
        return str;
    }

    func PickValueInList<T>(from list: T) -> T.Element where T: Collection {
        return list[Int.random(in: 0..<list.count) as! T.Index]
    }

//    func ConsumeBool() -> Bool {
//        return 1
//    }

}
