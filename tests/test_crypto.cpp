#include <QtTest>
#include "qtcryptng.h"

using namespace qtng;

class TestCrypto: public QObject
{
    Q_OBJECT
private slots:
    void testMd4();
    void testMd5();
    void testSha1();
    void testSha224();
    void testSha256();
    void testSha384();
    void testSha512();
    void testRipemd160();
//    void testBlake2b512();
//    void testBlake2s256();
    void testAES128();
    void testAES256();
    void testBlowfish();
    void testDecrypt();
    void testGenRSA();
    void testSignRSA();
    void testCryptoRSA();
    void testSaveLoadRsa();
    void testGenDSA();
    void testSignDSA();
//    void testCryptoDSA();
    void testCertificate();
};

void TestCrypto::testMd4()
{
    QCOMPARE(MessageDigest::hash("123456", MessageDigest::Md4), QByteArray("585028aa0f794af812ee3be8804eb14a"));
}

void TestCrypto::testMd5()
{
    QCOMPARE(MessageDigest::hash("123456", MessageDigest::Md5), QByteArray("e10adc3949ba59abbe56e057f20f883e"));
}

void TestCrypto::testSha1()
{
    QCOMPARE(MessageDigest::hash("123456", MessageDigest::Sha1), QByteArray("7c4a8d09ca3762af61e59520943dc26494f8941b"));
}

void TestCrypto::testSha224()
{
    QCOMPARE(MessageDigest::hash("123456", MessageDigest::Sha224), QByteArray("f8cdb04495ded47615258f9dc6a3f4707fd2405434fefc3cbf4ef4e6"));
}

void TestCrypto::testSha256()
{
    QCOMPARE(MessageDigest::hash("123456", MessageDigest::Sha256), QByteArray("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"));
}

void TestCrypto::testSha384()
{
    QCOMPARE(MessageDigest::hash("123456", MessageDigest::Sha384), QByteArray("0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454"));
}

void TestCrypto::testSha512()
{
    QCOMPARE(MessageDigest::hash("123456", MessageDigest::Sha512), QByteArray("ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413"));
}

void TestCrypto::testRipemd160()
{
    QCOMPARE(MessageDigest::hash("123456", MessageDigest::Ripemd160), QByteArray("d8913df37b24c97f28f840114d05bd110dbb2e44"));
}

//void TestSsl::testBlake2b512()
//{
//    QCOMPARE(QMessageDigest::hash("123456", QMessageDigest::Blake2b512), QByteArray("ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413"));
//}

//void TestSsl::testBlake2s256()
//{
//    QCOMPARE(QMessageDigest::hash("123456", QMessageDigest::Blake2s256), QByteArray("ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413"));
//}

void TestCrypto::testAES128()
{
    Cipher c(Cipher::AES128, Cipher::ECB, Cipher::Encrypt);
    c.setPassword("123456", MessageDigest::Sha256, "12345678", 1);
    QByteArray result;
    result.append(c.addData("fish is here."));
    result.append(c.finalData());
    result = c.saltHeader() + result;
    // echo -n "fish is here." | openssl enc -aes-128-ecb -e -a -k 123456 -S 3132333435363738 -md sha256
    const QByteArray &expected = QByteArray::fromBase64("U2FsdGVkX18xMjM0NTY3ODCN9CMMP0w/Z/DnrpiyrW8=");
    QCOMPARE(result, expected);
}

void TestCrypto::testAES256()
{
    Cipher c(Cipher::AES256, Cipher::ECB, Cipher::Encrypt);
    c.setPassword("123456", MessageDigest::Sha256, "12345678", 1);
    QByteArray result;
    result.append(c.addData("fish is here."));
    result.append(c.finalData());
    result = c.saltHeader() + result;
    // echo -n "fish is here." | openssl enc -aes-256-ecb -e -a -k 123456 -S 3132333435363738 -md sha256
    const QByteArray &expected = QByteArray::fromBase64("U2FsdGVkX18xMjM0NTY3OE/gHqpPX7acGTjwZUY3UFM=");
    QCOMPARE(result, expected);
}

void TestCrypto::testBlowfish()
{
    Cipher c(Cipher::Blowfish, Cipher::ECB, Cipher::Encrypt);
    c.setPassword("123456", MessageDigest::Sha256, "12345678", 1);
    QByteArray result;
    result.append(c.addData("fish is here."));
    result.append(c.finalData());
    result = c.saltHeader() + result;
    // echo -n "fish is here." | openssl enc -bf -e -a -k 123456 -S 3132333435363738 -md sha256
    const QByteArray &expected = QByteArray::fromBase64("U2FsdGVkX18xMjM0NTY3OFGWlCvnFhkIuQ+UJL7SC0g=");
    QCOMPARE(result, expected);
}


void TestCrypto::testDecrypt()
{
    Cipher c1(Cipher::Blowfish, Cipher::ECB, Cipher::Encrypt);
    c1.setPassword("123456", MessageDigest::Sha256, "12345678", 1);
    QByteArray encryptedText;
    encryptedText.append(c1.addData("fish is here."));
    encryptedText.append(c1.finalData());

    Cipher c2(Cipher::Blowfish, Cipher::ECB, Cipher::Decrypt);
    c2.setPassword("123456", MessageDigest::Sha256, "12345678", 1);
    QByteArray clearText;
    clearText.append(c2.addData(encryptedText));
    clearText.append(c2.finalData());

    QCOMPARE(clearText, QByteArray("fish is here."));
}


void TestCrypto::testGenRSA()
{
    PrivateKey key1 = PrivateKey::generate(PrivateKey::Rsa, 2048);
    PrivateKey key2 = PrivateKey::generate(PrivateKey::Rsa, 1024);
    QVERIFY(key1.isValid());
    QVERIFY(key2.isValid());
    QVERIFY(key1.algorithm() == PrivateKey::Rsa);
    QVERIFY(key2.algorithm() == PrivateKey::Rsa);
    QVERIFY(key1.bits() == 2048);
    QVERIFY(key2.bits() == 1024);
}

void TestCrypto::testSignRSA()
{
    PrivateKey key = PrivateKey::generate(PrivateKey::Rsa, 2048);
    const QByteArray &signedText = key.sign("123456", MessageDigest::Sha512);
    QVERIFY(!signedText.isEmpty());
    QVERIFY(key.verify("123456", signedText, MessageDigest::Sha512));
}


void TestCrypto::testCryptoRSA()
{
    PrivateKey key = PrivateKey::generate(PrivateKey::Rsa, 2048);
    QByteArray text = randomBytes(64);
    QByteArray entext = key.encrypt(text);
    QCOMPARE(key.decrypt(entext), text);
    QByteArray entext2 = key.rsaPrivateEncrypt(text, PrivateKey::RSA_PKCS1_PADDING);
    QCOMPARE(key.rsaPublicDecrypt(entext2, PrivateKey::RSA_PKCS1_PADDING), text);
    QByteArray entext3 = key.rsaPublicEncrypt(text, PrivateKey::RSA_PKCS1_OAEP_PADDING);
    QCOMPARE(key.rsaPrivateDecrypt(entext3, PrivateKey::RSA_PKCS1_OAEP_PADDING), text);
}

void TestCrypto::testSaveLoadRsa()
{
    PrivateKey key1 = PrivateKey::generate(PrivateKey::Rsa, 2048);
    QByteArray pem = PrivateKeyWriter(key1).setCipher(Cipher::AES256, Cipher::CBC).setPassword("123456").asPem();
    QByteArray pem2 = key1.savePublic();
    qDebug() << pem2;
    QVERIFY(!pem2.isEmpty());
    PrivateKey key2 = PrivateKeyReader().setFormat(Ssl::Pem).setPassword("123456").read(pem);

    PrivateKey key3 = PrivateKey::generate(PrivateKey::Rsa, 2048);
    PublicKey key4 = PrivateKeyReader().setFormat(Ssl::Pem).readPublic(pem2);
    qDebug() << key4.save();
    QCOMPARE(key1, key2);
    QVERIFY(key1 != key3);
    QVERIFY(key4.isValid());
}

void TestCrypto::testGenDSA()
{
    PrivateKey key1 = PrivateKey::generate(PrivateKey::Dsa, 2048);
    PrivateKey key2 = PrivateKey::generate(PrivateKey::Dsa, 1024);
    QVERIFY(key1.isValid());
    QVERIFY(key2.isValid());
    QVERIFY(key1.algorithm() == PrivateKey::Dsa);
    QVERIFY(key2.algorithm() == PrivateKey::Dsa);
    QVERIFY(key1.bits() == 2048);
    QVERIFY(key2.bits() == 1024);
}

void TestCrypto::testSignDSA()
{
    PrivateKey key = PrivateKey::generate(PrivateKey::Dsa, 2048);
    const QByteArray &signedText = key.sign("123456", MessageDigest::Sha512);
    QVERIFY(!signedText.isEmpty());
    QVERIFY(key.verify("123456", signedText, MessageDigest::Sha512));
}

//void TestCrypto::testCryptoDSA()
//{
//    PrivateKey key = PrivateKey::generate(PrivateKey::Dsa, 2048);
//    QByteArray text = randomBytes(16);
//    QByteArray entext = key.encrypt(text);
//    QCOMPARE(key.decrypt(entext), text);
//}

QString first(const QStringList &l) {
    if(l.size() > 0) {
        return l.at(0);
    } else {
        return QString();
    }
}

void TestCrypto::testCertificate()
{
    PrivateKey pkey = PrivateKey::generate(PrivateKey::Rsa, 2048);
    const QDateTime &now = QDateTime::currentDateTime();
    QMultiMap<Certificate::SubjectInfo, QString> subjectInfoes = {
        { Certificate::Organization, QStringLiteral("Gigacores") },
        { Certificate::CommonName, QStringLiteral("Goldfish") },
        { Certificate::CountryName, QStringLiteral("CN") },
    };
    Certificate cert = Certificate::generate(pkey, MessageDigest::Sha256, 29472, now, now.addYears(10), subjectInfoes);
    QVERIFY(!cert.isNull());
    QVERIFY(qAbs(cert.effectiveDate().msecsTo(now)) < 1000);
    QVERIFY(qAbs(cert.expiryDate().msecsTo(now.addYears(10))) < 1000);
    QCOMPARE(first(cert.issuerInfo(Certificate::Organization)), QStringLiteral("Gigacores"));
    QCOMPARE(first(cert.issuerInfo(Certificate::CommonName)), QStringLiteral("Goldfish"));
    QCOMPARE(first(cert.issuerInfo(Certificate::CountryName)), QStringLiteral("CN"));
    QVERIFY(cert.isSelfSigned());
    QVERIFY(cert.publicKey().isValid());
    QByteArray pem = cert.save();
    const Certificate &cert2 = Certificate::load(pem);
//    qDebug() << cert << cert2 << cert.save() << cert2.save();
//    QVERIFY(cert.save() == cert2.save());
    QVERIFY(cert == cert2);
}

QTEST_MAIN(TestCrypto)

#include "test_crypto.moc"
