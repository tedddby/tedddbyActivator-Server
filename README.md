# Apple Device Activation Server Emulator

This PHP-based project served as the **main activation server for [`tedddbyActivator`](https://github.com/tedddby/tedddbyActivator-Poject)** — a powerful iCloud bypass solution for jailbroken Apple devices. Unlike simulated tools, this activation server was **fully functional**, generating legitimate activation responses accepted by real devices during the bypass process.

> ⚠️ **Disclaimer:** This tool is intended for **educational and security research purposes only**. Unauthorized use on devices you do not own or have permission to operate on may be illegal in your country.

---

## 🚫 Notice (2023)

Apple has **patched** the activation methods used by this server as of **2023**.  
The project is **no longer functional**, and is archived here **for reference and educational purposes only**.

---

## 🚀 Features

- Fully emulated Apple's `albert.apple.com/deviceservices/deviceActivation` endpoint.
- Generated activation records (`activation_record.plist`) accepted by actual iPhones and iPads.
- Signed activation requests using embedded RSA private keys and Apple FairPlay certificate chains.
- Supported baseband ticket generation and proper token signing.
- Outputted FairPlay key data, device certificates, and account tokens.

---

## 🛠️ Technologies Used

- **PHP**: Core backend logic.
- **OpenSSL**: RSA signature generation and certificate handling.
- **cURL**: Communicated with Apple’s services or responded locally.
- **Plist XML**: Structured data format for activation records.
- **Apple FairPlay Certificates**: Included to mimic secure Apple authentication chains.

---

## 📁 Project Structure

```
activation/
├── ac.php                  # Main entry point handling activation logic
├── Center.php              # Handles saving Wildcard tickets
├── FairplayCerts/          # FairPlay certificate files (.crt, .der)
├── infos/                  # Contains wildcard and info response scripts
├── ActivationFiles/        # Output directory for activation assets
├── delete, info, error_log # Log and support files
```

---

## ⚙️ Setup Instructions

> Requires PHP >= 7.0 with `openssl` and `curl` extensions enabled.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/apple-activation-emulator.git
   cd apple-activation-emulator/activation
   ```

2. **Start the local server:**
   ```bash
   php -S localhost:8080
   ```

3. **Device Configuration**:
   - Modify device DNS or redirect activation traffic to your local server.
   - Compatible with `tedddbyActivator` for seamless bypass flow.

4. **Check output**:
   - Files saved inside `ActivationFiles/<SerialNumber>/`:
     - `activation_record.plist`
     - `Wildcard.der`
     - FairPlay key data and account tokens

---

## 📌 Important Notes

- It powered the **main activation backend for `tedddbyActivator`**, a legacy iCloud bypass service.
- Since **2023**, Apple has **patched and revoked** the mechanisms that made this possible.
- Retained for historical and research purposes only.

---

## 👨‍💻 Author

Originally developed by the creator of [tedddbyActivator](https://github.com/tedddby)  
For research, development, and security education only.  
No warranty or support is provided.
