# SecureDocs
This project harnesses the capabilities of identity based signatures and encryption for authentic end-to-end secure document sharing.

To run the project on your Linux machine:

Clone the repository in your machine.

Open the terminal in the root directory.

Ensure that you have installed node.js on your machine. If not, you may run the following command:
```bash
sudo apt update
sudo apt install nodejs npm
```

Ensure that you have installed mongodb compass and create two clusters.

To test whether it has been installed:
```bash
node -v npm -v
```

Now, in the root directory, run:
```bash
npm install
cd server
npm install
cd ../kdc
npm install
cd ../client
npm install
```

## Environment Configuration

Create `.env` files in the **server**, **kdc**, and **client** directories with the following structure:

---

### `client/.env`
```env
VITE_API_BASE_URL="http://localhost:5006/api"

VITE_KDC_BASE_URL="http://localhost:5007/api"
```
### `server/.env`
```env
MONGO_URI="Your-mongodb-cluster-uri"
JWT_SECRET="A-long-random-string"
```

### `kdc/.env`
```env
MONGO_URI="Your-mongodb-cluster-uri-different-cluster-to-be-used-here"

JWT_SECRET="The-same-long-random-string"

NATIVE_CRYPTO_DIR=/path-to-project-root-directory/kdc/opt/crypto-native
NATIVE_KEYGEN_EXEC=keygen
NATIVE_PARAM_FILE=a.param
NATIVE_MSK_FILE=master_secret_key.dat

EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=465 # Use 465 for SSL, or 587 for TLS
EMAIL_SECURE=true # Use true for 465, false for 587 (will use STARTTLS)
EMAIL_USER=example@iiita.ac.in # The email address you send FROM
EMAIL_PASS=**** # The 16-character App Password
EMAIL_FROM='secure-doc-platform example@iiita.ac.in'
```

Go to /kdc/opt/crypto-native
```bash
chmod +x keygen
```

Now, in three separate terminals, one in client, one in kdc, and one in server, run:
```bash
npm run dev
```

Now, you can go to http://localhost:5173/ and use the GUI.
