import Foundation
import CommonCrypto

class HashManager {
    static let shared = HashManager()
    
    private init() {
        
    }
    
    enum HashAlgorithm {
        case sha1, sha256, sha512, md5
    }
    
    var file1Data: Data?
    var file2Data: Data?

    func verifyFile(file1Data: Data, fileName: String, file2Data: Data) -> Bool {
        let hashResult = hash(data: file1Data)
        print("Hash of file1Data (\(fileName)): \(hashResult)")
        
        let file2Contents = String(data: file2Data, encoding: .utf8) ?? ""
        print("Contents of file2Data:\n\(file2Contents)")

        let sanitizedFile2Contents = file2Contents.components(separatedBy: CharacterSet.alphanumerics.inverted).joined()
        let searchString = "\(hashResult)\(fileName.components(separatedBy: CharacterSet.alphanumerics.inverted).joined())"
        
        print("Searching for string in sanitized file2Data: \(searchString)")
        
        let verificationSuccess = sanitizedFile2Contents.contains(searchString)
        print("Verification Result: \(verificationSuccess ? "Successful" : "Failed")")
        return verificationSuccess
    }

    var selectedAlgorithm: HashAlgorithm = .sha256 {
        didSet {
            print("Selected hash algorithm changed to: \(selectedAlgorithm)")
        }
    }
    
    func performHash(data: Data, delegate: HashProtocol) {
        let hashResult = hash(data: data)
        delegate.didHashFile(algorithm: selectedAlgorithm, hash: hashResult)
    }
    
    private func hash(data: Data) -> String {
        switch selectedAlgorithm {
        case .sha256:
            return hashSHA256(data: data)
        case .md5:
            return hashMD5(data: data)
        case .sha1:
            return hashSHA1(data: data)
        case .sha512:
            return hashSHA512(data: data)
        }
    }
    
    private func hashSHA256(data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    private func hashMD5(data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    private func hashSHA1(data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
    
    private func hashSHA512(data: Data) -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA512($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
