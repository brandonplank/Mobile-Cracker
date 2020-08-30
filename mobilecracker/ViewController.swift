//
//  ViewController.swift
//  iospasshash
//
//  Created by Brandon Plank on 8/19/20.
//  Copyright © 2020 Brandon Plank. All rights reserved.
//

import UIKit
import Foundation
import CommonCrypto
import MachO
import CryptoKit
import BCrypt

struct Sha512 {
    let context = UnsafeMutablePointer<CC_SHA512_CTX>.allocate(capacity:1)
    init() {
        autoreleasepool(){
            CC_SHA512_Init(context)
        }
    }
    func update(data: Data) {
        data.withUnsafeBytes { (bytes: UnsafePointer<Int8>) -> Void in
            let end = bytes.advanced(by: data.count)
            for f in sequence(first: bytes, next: { $0.advanced(by: Int(CC_LONG.max)) }).prefix(while: { (current) -> Bool in current < end})  {
                _ = CC_SHA512_Update(context, f, CC_LONG(Swift.min(f.distance(to: end), Int(CC_LONG.max))))
            }
        }
    }
    func final() -> Data {
        autoreleasepool(){
            var digest = [UInt8](repeating: 0, count:Int(CC_SHA512_DIGEST_LENGTH))
            CC_SHA512_Final(&digest, context)
            return Data(bytes: digest)
        }
    }
}

struct Sha256 {
    let context = UnsafeMutablePointer<CC_SHA256_CTX>.allocate(capacity:1)
    init() {
        autoreleasepool(){
            CC_SHA256_Init(context)
        }
    }
    func update(data: Data) {
        data.withUnsafeBytes { (bytes: UnsafePointer<Int8>) -> Void in
            let end = bytes.advanced(by: data.count)
            for f in sequence(first: bytes, next: { $0.advanced(by: Int(CC_LONG.max)) }).prefix(while: { (current) -> Bool in current < end})  {
                _ = CC_SHA256_Update(context, f, CC_LONG(Swift.min(f.distance(to: end), Int(CC_LONG.max))))
            }
        }
    }
    func final() -> Data {
        autoreleasepool(){
            var digest = [UInt8](repeating: 0, count:Int(CC_SHA256_DIGEST_LENGTH))
            CC_SHA256_Final(&digest, context)
            return Data(bytes: digest)
        }
    }
}

extension Data {
    func sha512() -> Data {
        let s = Sha512()
        s.update(data: self)
        return s.final()
    }
    
    func sha256() -> Data {
        let s = Sha256()
        s.update(data: self)
        return s.final()
    }
}

extension String {
    func sha512() -> Data {
        return self.data(using: .utf8)!.sha512()
    }
    var md5: String {
        let data = Data(self.utf8)
        let hash = data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) -> [UInt8] in
            var hash = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
            CC_MD5(bytes.baseAddress, CC_LONG(data.count), &hash)
            return hash
        }
        let hashmd5 = hash.map { String(format: "%02x", $0) }.joined()
        let characterset = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        if hashmd5.rangeOfCharacter(from: characterset.inverted) != nil {
            print("string contains special characters")
            return "Error, hash is invalid"
        }
        return hashmd5
    }
    func sha256() -> Data {
        return self.data(using: .utf8)!.sha256()
    }
}

func HashFile(_ file: String) -> String{
    let path = "\(file)"
    let url = URL(fileURLWithPath: path)
    let data = try! Data(contentsOf: url)
    let sum = "\(data.sha512().map { String(format: "%02hhx", $0) }.joined())"
    return sum
}

class ViewController: UIViewController {
    
    var hashMethod = "SHA512"//Default
    
    @IBOutlet weak var passView: UILabel!
    @IBOutlet weak var password: UILabel!
    @IBOutlet weak var hashview: UILabel!
    @IBOutlet weak var per_second: UILabel!
    @IBOutlet weak var userHash: UITextField!
    
    @IBOutlet weak var segmentedControl: UISegmentedControl!
    
    //Calls this function when the tap is recognized.
    @objc func dismissKeyboard() {
        //Causes the view (or one of its embedded text fields) to resign the first responder status.
        view.endEditing(true)
    }
    
    var textField: UITextField?
    var canread = true

    func configurationTextField(textField: UITextField!) {
        if (textField) != nil {
            self.textField = textField!        //Save reference to the UITextField
            self.textField?.placeholder = "Password";
        }
    }
    
    func getHashFromType(_ text: String) -> String {
        var hash: String = ""
        switch self.hashMethod {
        case "SHA512":
            switch canread {
            case true:
                hash = "\(text.sha512().map { String(format: "%02hhx", $0) }.joined())"
            default:
                print("Not making blank SHA256")
                hash = "None"
            }
        case "BCrypt":
            switch canread {
            case true:
                hash = try! BCrypt.Hash.make(message: text).makeString()
            default:
                print("Not making blank BCrypt")
                hash = "None"
            }
        case "SHA256":
            switch canread {
            case true:
                hash = "\(text.sha256().map { String(format: "%02hhx", $0) }.joined())"
            default:
                print("Not making blank SHA256")
                hash = "None"
            }
        case "MD5":
            switch canread {
            case true:
                hash = "\(text.md5)"
            default:
                print("Not making blank md5")
                hash = "None"
            }
        default:
            break
        }
        return hash
    }
    
    @IBAction func passwordHashFunction(_ sender: Any) {
        DispatchQueue.main.async {
            let alert = UIAlertController(title: "Notice", message: "Please input a password", preferredStyle: UIAlertController.Style.alert)
            alert.addTextField(configurationHandler: self.configurationTextField)
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler:nil))
            alert.addAction(UIAlertAction(title: "Ok", style: .default, handler: { action in
                self.dismiss(animated: true, completion: {
                    if self.textField?.text == nil || self.textField?.text! == ""{
                        let alert2 = UIAlertController(title: "Error", message: "Please input a password.", preferredStyle: .alert)
                        alert2.addAction(UIKit.UIAlertAction(title: "OK", style: .default, handler: { action in
                        }))
                        self.present(alert2, animated: true, completion: nil)
                    } else {
                        print("hashing")
                        var hash: String = ""
                        let inputtedText = self.textField?.text
                        hash = self.getHashFromType(inputtedText!)
                        UIPasteboard.general.string = hash
                        let alert2 = UIAlertController(title: "Notice", message: "\(self.hashMethod): \(hash)\n\nCopied to clipboard!", preferredStyle: .alert)
                        alert2.addAction(UIKit.UIAlertAction(title: "OK", style: .default, handler: { action in
                              switch action.style{
                              case .default:
                                    print("default")

                              case .cancel:
                                    print("cancel")

                              case .destructive:
                                    print("destructive")
                              @unknown default:
                                break
                            }}))
                        self.present(alert2, animated: true, completion: nil)
                        
                    }
                })
            }))
            self.present(alert, animated: true, completion: nil)
        }
    }
    
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        //Looks for single or multiple taps.
        let tap: UITapGestureRecognizer = UITapGestureRecognizer(target: self, action: #selector(UIInputViewController.dismissKeyboard))

        //Uncomment the line below if you want the tap not not interfere and cancel other interactions.
        //tap.cancelsTouchesInView = false

        view.addGestureRecognizer(tap)
    }
    
    @IBAction func indexChanged(_ sender: Any) {
        switch segmentedControl.selectedSegmentIndex {
        case 0:
            print("Using SHA512")
            hashMethod = "SHA512"
        case 1:
            print("Using MD5")
            hashMethod = "MD5"
        case 2:
            print("Using SHA256")
            hashMethod = "SHA256"
        case 3:
            print("Using BCrypt")
            hashMethod = "BCrypt"
        default:
            break
        }
    }
    
    @IBAction func hash(_ sender: Any) {
        DispatchQueue.global(qos: .userInteractive).async {
            var actualPassword: String = ""
            var timeTook: Double = 0.0
            var canRunWild = true
            print("Starting hash crack, this may take a while!")
            let time = CFAbsoluteTimeGetCurrent()
            let filePath = Bundle.main.path(forResource: "10-million-passwords", ofType: "txt")
            let path = filePath
            var pass_hash: String = ""
            
            var didFindPassword = false
            DispatchQueue.main.async {
                if self.userHash.text == nil || self.userHash.text == ""{
                    DispatchQueue.main.async {
                            let alert = UIAlertController(title: "Error", message: "Please input a hash!", preferredStyle: .alert)
                            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: { action in
                            switch action.style{
                            case .default:
                                print("default")
                            case .cancel:
                                print("cancel")

                            case .destructive:
                                print("destructive")
                            @unknown default:
                                break
                            }}))
                        self.present(alert, animated: true, completion: nil)
                    }
                    return
                } else {
                    canRunWild = true
                    DispatchQueue.main.async {
                        pass_hash = self.userHash.text!
                    }
                    DispatchQueue.global(qos: .userInteractive).async {
                        if canRunWild || pass_hash != ""{
                            if freopen(path, "r", stdin) == nil {
                                perror(path)
                            }
                            
                            var passwordsCrackedCache = 0
                            var time_ = CFAbsoluteTimeGetCurrent()
                            
                            var hash: String
                            var i = 0
                            //now start :o
                            while let line = readLine() {
                                DispatchQueue.main.async {
                                    self.password.text = "Password: \(line)"
                                }
                                i+=1
                                passwordsCrackedCache+=1
                                switch line {
                                case "":
                                    print("Detected blank line, not trying to read that.")
                                    self.canread = false
                                default:
                                    self.canread = true
                                    break
                                }
                                hash = self.getHashFromType(line)
                                DispatchQueue.main.async {
                                    switch self.canread{
                                    case true:
                                        self.hashview.text = "Hash: \(hash)"
                                    default:
                                        self.hashview.text = "Hash: None"
                                    }
                                }
                                
                                switch hash {
                                case pass_hash:
                                    print(hash)
                                    timeTook = CFAbsoluteTimeGetCurrent() - time
                                    print("We got a match!\nPassword is \(line)\nFinished in \(timeTook) seconds, processed \(i) passwords!\nAt a average of \(Double(i) / timeTook) passwords a second")
                                    actualPassword = line
                                    didFindPassword = true
                                    switch didFindPassword {
                                    case true:
                                        DispatchQueue.main.async {
                                            let alert = UIAlertController(title: "Notice", message: "We got a match!\nPassword is \(actualPassword)\nFinished in \(timeTook) seconds, processed \(i) passwords!\nAt a average of \(Double(i) / timeTook) passwords a second", preferredStyle: .alert)
                                            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: { action in
                                                  switch action.style{
                                                  case .default:
                                                        print("default")

                                                  case .cancel:
                                                        print("cancel")

                                                  case .destructive:
                                                        print("destructive")
                                                  @unknown default:
                                                    break
                                                }}))
                                            self.present(alert, animated: true, completion: nil)
                                        }
                                    default:
                                        break
                                    }
                                    return
                                default:
                                    DispatchQueue.main.async {
                                        self.passView.text = "Hashes scanned: \(i)"
                                    }
                                    DispatchQueue.main.async {
                                        if CFAbsoluteTimeGetCurrent() >= time_ + 1{
                                            self.per_second.text = "Hashes per second: \(Double(passwordsCrackedCache))"
                                            passwordsCrackedCache = 0
                                            time_ = CFAbsoluteTimeGetCurrent()
                                        }
                                    }
                                }
                            }
                            switch didFindPassword {
                            case true:
                                print("Finished")
                            default:
                                DispatchQueue.main.async {
                                    let alert = UIAlertController(title: "Notice", message: "We was unable to find a password with that hash.", preferredStyle: .alert)
                                    alert.addAction(UIAlertAction(title: "OK", style: .default, handler: { action in
                                          switch action.style{
                                          case .default:
                                                print("default")

                                          case .cancel:
                                                print("cancel")

                                          case .destructive:
                                                print("destructive")
                                          @unknown default:
                                            break
                                        }}))
                                    self.present(alert, animated: true, completion: nil)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

