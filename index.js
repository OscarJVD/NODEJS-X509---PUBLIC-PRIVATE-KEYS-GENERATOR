const { generateKeyPairSync } = require('crypto');
const fs = require('fs')
let forge = require('node-forge');
let pki = forge.pki;

// generate a keypair or use one you have already
let keys = pki.rsa.generateKeyPair(2048);

// create a new certificate
let cert = pki.createCertificate();

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 4096,  // the length of your key in bits
    publicKeyEncoding: {
        type: 'spki',       // recommended to be 'spki' by the Node.js docs
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',      // recommended to be 'pkcs8' by the Node.js docs
        format: 'pem',
        cipher: 'aes-256-cbc',   // *optional*
        passphrase: 'top secret' // *optional*
    }
});

function makeid(length) {
    var result = '';
    var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for (var i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() *
            charactersLength));
    }
    return result;
}

const privateKeyArchName = makeid(12);

fs.appendFile(`private/privatekey_${privateKeyArchName}.pem`, privateKey, (err) => {
    if (err) throw err;
    console.log('Archivo Llave privada Creado Satisfactoriamente');
});

// const publicKeyArchName = makeid(12);

// fs.appendFile(`public/publickey_${publicKeyArchName}.pem`, publicKey, (err) => {
//     if (err) throw err;
//     console.log('Archivo Llave publica Creado Satisfactoriamente');
// });

// fill the required fields
cert.publicKey = keys.publicKey;
// cert.publicKey = publicKey;
cert.serialNumber = '01';
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

// use your own attributes here, or supply a csr (check the docs)
var attrs = [{
    name: 'commonName',
    value: 'example.org'
}, {
    name: 'countryName',
    value: 'US'
}, {
    shortName: 'ST',
    value: 'Virginia'
}, {
    name: 'localityName',
    value: 'Blacksburg'
}, {
    name: 'organizationName',
    value: 'Test'
}, {
    shortName: 'OU',
    value: 'Test'
}];

// here we set subject and issuer as the same one
cert.setSubject(attrs);
cert.setIssuer(attrs);

// the actual certificate signing
cert.sign(keys.privateKey);

// now convert the Forge certificate to PEM format
let certx509 = pki.certificateToPem(cert);
console.log(certx509);

const x509ArchName = makeid(12);

fs.appendFile(`certs/x509_${x509ArchName}.pem`, certx509, (err) => {
    if (err) throw err;
    console.log('Certificado X.509 Creado Satisfactoriamente');
});

console.log(certx509);
// console.log(publicKey);
console.log(privateKey);