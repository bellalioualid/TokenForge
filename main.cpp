#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QCheckBox>
#include <QLineEdit>
#include <QGridLayout>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageAuthenticationCode>
#include <QByteArray>
#include <QMessageBox>


// declaration for getHashAlgorithm
QCryptographicHash::Algorithm getHashAlgorithm(const QString &algorithm);

// Function to encode in base64url
//
QString base64UrlEncode(const QByteArray &input) {
    QByteArray base64 = input.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    return QString(base64);
}
// Function to decode base64url
QByteArray base64UrlDecode(const QString &input) {
    // Replace URL-safe characters
    QString base64 = input;
    base64.replace('-', '+').replace('_', '/').append(QString(base64.length() % 4, '='));
    // Decode base64
    QByteArray decoded = QByteArray::fromBase64(base64.toUtf8(), QByteArray::Base64UrlEncoding);

    return decoded;
}
// Decode the secret key using base64 if the checkbox is checked, otherwise convert to UTF-8.
QByteArray decodeSecretKey(const QString &secretKey, QCheckBox *base64CheckBox) {
    // Check if the checkbox is checked
    if (base64CheckBox->isChecked()) {
        return QByteArray::fromBase64(secretKey.toUtf8());// secret key decoded
    } else {
        return secretKey.toUtf8();//key normal comme test
    }
}

// Validates if the input string is a non-empty and well-formed JSON object
//si linput est non vide et bien define json format
bool isValidJson(const QString &jsonString) {
    QJsonDocument jsonDoc = QJsonDocument::fromJson(jsonString.toUtf8());
    return jsonDoc.isObject();
}






// Function to check if the algorithm in the header matches the selected algorithm
//il verifie si l'algo compatible avec algo selected
//
bool isHeaderValid(const QJsonObject &header,const QString &algorithm) {
    if ((header.contains("alg") && header["alg"].isString()) && (header.contains("typ") && header["typ"].isString() && header["typ"] == "JWT")) {
        QString headerAlgorithm = header["alg"].toString();
        return (headerAlgorithm == algorithm);
    }
    return false;
}





// Function to generate a JWT
//la geniration de JWT (encoding)
QString generateJwt(const QJsonObject &header, const QJsonObject &payload, const QString &secretKey, const QString &algorithm, bool secretBase64Encoded) {
    // Encode in base64url
    //convert header and payload json object into compact json forma type QbyteArray
    QByteArray headerBytes = QJsonDocument(header).toJson(QJsonDocument::Compact);  // ie sous form {JDlkhLKEDHQkldhqKLDHQlksdh} in line
    QByteArray payloadBytes = QJsonDocument(payload).toJson(QJsonDocument::Compact);//

    QString encodedHeader = base64UrlEncode(headerBytes);
    QString encodedPayload = base64UrlEncode(payloadBytes);

    // Concatenate the parts
    QString data = encodedHeader + '.' + encodedPayload;

    // Base64 decode the secret key if needed
    QString decodedSecretKey = secretBase64Encoded ? QString(QByteArray::fromBase64(secretKey.toUtf8())) : secretKey;//if else


    // Generate the signature
    QByteArray signature = QMessageAuthenticationCode::hash(data.toUtf8(), secretKey.toUtf8(), getHashAlgorithm(algorithm));
    //QMessageAuthenticationCode pre definie
    // Concatenate to get the JWT
    QString jwtToken = data + '.' + base64UrlEncode(signature);

    return jwtToken;
}
QCryptographicHash::Algorithm getHashAlgorithm(const QString &algorithm) {
    if (algorithm == "HS256") {
        return QCryptographicHash::Sha256;
    } else if (algorithm == "HS384") {
        return QCryptographicHash::Sha384;
    } else if (algorithm == "HS512") {
        return QCryptographicHash::Sha512;
    }
}


// Function to decode a JSON Web Token (JWT) and extract the payload.
QJsonObject decodeJwt(const QString &jwt, const QString &secretKey, QString &decodedAlgorithm, QComboBox *comboBox, QTextEdit *textEdit, bool secretBase64Encoded) {
    // Split the JWT into its components
    QStringList parts = jwt.split('.');

    // Extract the encoded header and payload and signature
    QString encodedHeader = parts.at(0);
    QString encodedPayload = parts.at(1);
    QString encodedSignature = parts.at(2);

    QByteArray headerBytes;
    QByteArray payloadBytes;
    QByteArray signatureBytes;

    // Decode base64url to obtain header, payload, and signature bytes
    headerBytes = QByteArray::fromBase64(encodedHeader.toUtf8(), QByteArray::Base64UrlEncoding);
    payloadBytes = QByteArray::fromBase64(encodedPayload.toUtf8(), QByteArray::Base64UrlEncoding);
    //frombase64 predefind to decode 64url
    signatureBytes = QByteArray::fromBase64(encodedSignature.toUtf8());

    // Convert decoded bytes to JSON objects
    QJsonObject header = QJsonDocument::fromJson(headerBytes).object();
    QJsonObject payload = QJsonDocument::fromJson(payloadBytes).object();


    // Set the decoded algorithm from the header, if available
    if (header.contains("alg") && header["alg"].isString()) {
        decodedAlgorithm = header["alg"].toString();
    } else {
        // If the algorithm is not found in the header, use the algorithm from the combo box
        decodedAlgorithm = comboBox->currentText();
    }

    // Base64 decode the secret key if needed
    QByteArray decodedSecretKey = secretBase64Encoded ? QByteArray::fromBase64(secretKey.toUtf8()) : secretKey.toUtf8();

    // Prepare HTML content with different colors for encoded token
    QString htmlContent = "<span style='color: red;'>" + encodedHeader + "</span>"
                                                                         "<span style='color: purple;'>." + encodedPayload + "</span>"
                                             "<span style='color: blue;'>." + encodedSignature + "</span><br>";

    // Display the HTML content in a QTextEdit or another suitable widget
    textEdit->setHtml(htmlContent);

    // Return the decoded payload along with the header
    QJsonObject result;
    result["header"] = header;//il affiche header dans case header
    result["payload"] = payload;//meme pour payload
    return result;
}
bool verifyJwtSignature(const QString &jwt, const QString &secretKey, const QString &algorithm, bool secretBase64Encoded) {
    // Split the JWT into its components
    QStringList parts = jwt.split('.');

    // Extract the encoded header, payload, and signature
    QByteArray headerBytes = base64UrlDecode(parts.at(0));
    QByteArray payloadBytes = base64UrlDecode(parts.at(1));
    QByteArray signatureBytes = QByteArray::fromBase64(parts.at(2).toUtf8(), QByteArray::Base64UrlEncoding);//*

    // Concatenate the header and payload to recreate the data used for signature generation
    QString data = parts.at(0) + '.' + parts.at(1);

    // Base64 decode the secret key if needed
    QByteArray decodedSecretKey = secretBase64Encoded ? QByteArray::fromBase64(secretKey.toUtf8()) : secretKey.toUtf8();
    //-----------------------------------------------DEBUGING----------------------------------------//
    qDebug() << "Decoded Secret Key:" << decodedSecretKey;//to see secret key to verifier dans console

    // Generate the expected signature
    QByteArray expectedSignature = QMessageAuthenticationCode::hash(data.toUtf8(), decodedSecretKey, getHashAlgorithm(algorithm));//decode key si is cheked

    qDebug() << "Expected Signature:" << expectedSignature.toBase64();//quil faux etre
    qDebug() << "Actual Signature:" << signatureBytes.toBase64();//la signature generer //*

    // Compare the computed signature with the one in the JWT
    if (signatureBytes == expectedSignature) {
        qDebug() << "Signature verification passed";
        return true;
    } else {
        qDebug() << "Signature verification failed";
        return false;
    }
    //-----------------------------------------------_______________-----------------------------------------------
}
void updateSignature(QTextEdit *tokenTextEdit, QTextEdit *headerTextEdit, QTextEdit *payloadTextEdit, const QString &secretKey, bool secretBase64Encoded, const QString &algorithm, QCheckBox *base64CheckBox) {
    // Encode in base64url
    QByteArray headerBytes = QJsonDocument::fromJson(headerTextEdit->toPlainText().toUtf8()).toJson(QJsonDocument::Compact);
    QByteArray payloadBytes = QJsonDocument::fromJson(payloadTextEdit->toPlainText().toUtf8()).toJson(QJsonDocument::Compact);

    QString encodedHeader = base64UrlEncode(headerBytes);
    QString encodedPayload = base64UrlEncode(payloadBytes);

    // Concatenate the parts
    QString data = encodedHeader + '.' + encodedPayload;

    // Base64 decode the secret key
    QByteArray decodedSecretKey = decodeSecretKey(secretKey, base64CheckBox);
    qDebug() << "Decoded Secret Key:" << decodedSecretKey;

    // Generate the signature

    //secret key decoded
    QByteArray signature = QMessageAuthenticationCode::hash(data.toUtf8(), decodedSecretKey, getHashAlgorithm(algorithm));
    qDebug() << "Generated Signature:" << signature.toBase64();

    // Prepare HTML content with different colors for encoded token
    QString htmlContent = "<span style='color: red;'>" + encodedHeader + "</span>"
                                                                         "<span style='color: purple;'>." + encodedPayload + "</span>"
                                             "<span style='color: blue;'>." + base64UrlEncode(signature) + "</span><br>";

    // Update the text edit with the new token/encoded text (signature)
    tokenTextEdit->setHtml(htmlContent);
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QWidget mainWindow;





    // Vertical Layout 1
    QVBoxLayout *verticalLayout1 = new QVBoxLayout;

    QLabel *headerLabel = new QLabel("<b>HEADER</b>");
    QTextEdit *headerTextEdit = new QTextEdit;
    QString headerHtmlContent = "<span style='color: red; font-family: inherit;'>{"
                                "<br>&nbsp;&nbsp;&nbsp;&nbsp;\"alg\": \"HS256\","
                                "<br>&nbsp;&nbsp;&nbsp;&nbsp;\"typ\": \"JWT\""
                                "<br>}</span>";
    headerTextEdit->setHtml(headerHtmlContent);
    headerTextEdit->setStyleSheet("background-color: #EDF3F8;");

    verticalLayout1->addWidget(headerLabel);
    verticalLayout1->addWidget(headerTextEdit);

    QLabel *payloadLabel = new QLabel("<b>PAYLOAD</b>");
    QTextEdit *payloadTextEdit = new QTextEdit;
    QString payloadHtmlContent = "<span style='color: purple; font-family: inherit;'>{"
                                 "<br>&nbsp;&nbsp;&nbsp;&nbsp;\"sub\": \"1234567890\","
                                 "<br>&nbsp;&nbsp;&nbsp;&nbsp;\"name\": \"John Doe\","
                                 "<br>&nbsp;&nbsp;&nbsp;&nbsp;\"iat\": 1516239022"
                                 "<br>}</span>";
    payloadTextEdit->setHtml(payloadHtmlContent);
    payloadTextEdit->setStyleSheet("background-color: #EDF3F8;");

    verticalLayout1->addWidget(payloadLabel);
    verticalLayout1->addWidget(payloadTextEdit);
    QLabel *signatureLabel2 = new QLabel("<b>VERIFY SIGNATURE</b>");
    verticalLayout1->addWidget(signatureLabel2);
    // Create a frame for the signature section
    QFrame *signatureFrame = new QFrame;
    signatureFrame->setFrameShape(QFrame::Box);  // Set the frame shape to Box for a border
    signatureFrame->setLineWidth(1);  // Set the border width

    QVBoxLayout *signatureLayout = new QVBoxLayout(signatureFrame);

    QLabel *signatureLabel = new QLabel("<b>VERIFY SIGNATURE</b>");

    //signatureLayout->addWidget(signatureLabel);

    // Declare and initialize QGridLayout for the signature section
    QGridLayout *gridLayout = new QGridLayout;

    QLineEdit *lineEdit = new QLineEdit;
    QString htmlPlaceholder = "Enter your signature";
    payloadTextEdit->setHtml(payloadHtmlContent);
    lineEdit->setPlaceholderText(htmlPlaceholder);
    lineEdit->setStyleSheet("color: blue;");
    lineEdit->setStyleSheet("background-color: #EDF3F8;");

    QLabel *label9 = new QLabel("HMACSHA256(\n  base64UrlEncode(header) + \".\" +\n  base64UrlEncode(payload),");
    // Set the initial style sheet to make the text blue
    label9->setStyleSheet("color: blue;");

    // Add the checkbox for "Secret Base64 Encoded"
    QCheckBox *base64CheckBox = new QCheckBox("Secret Base64 Encoded");
    gridLayout->addWidget(base64CheckBox, 2, 1);

    // Declare the variable at a higher scope
    bool secretBase64Encoded = base64CheckBox->isChecked();

    gridLayout->addWidget(lineEdit, 1, 1);
    gridLayout->addWidget(label9, 0, 1);

    signatureLayout->addLayout(gridLayout);
    signatureFrame->setStyleSheet("background-color: #EDF3F8;");
    verticalLayout1->addWidget(signatureFrame);

    // Vertical Layout 3
    QVBoxLayout *verticalLayout2 = new QVBoxLayout;

    QComboBox *comboBox = new QComboBox;
    comboBox->addItem("HS256");
    comboBox->addItem("HS384");
    comboBox->addItem("HS512");
    comboBox->setStyleSheet("background-color: #277FB6; color: #000000;font-weight: bold;");

    QPushButton *decodeButton = new QPushButton("DECODE");
    decodeButton->setStyleSheet("background-color: #277FB6; color: #000000;font-weight: bold;");
    QPushButton *encodeButton = new QPushButton("ENCODE");
    encodeButton->setStyleSheet("background-color: #277FB6; color: #000000;font-weight: bold;");
    QPushButton *clearButton  = new QPushButton("CLEAR");
    clearButton->setStyleSheet("background-color: #277FB6; color: #000000;font-weight: bold;");

    verticalLayout2->addWidget(comboBox);
    verticalLayout2->addWidget(decodeButton);
    verticalLayout2->addWidget(encodeButton);
    verticalLayout2->addWidget(clearButton);

    // Vertical Layout 2
    QVBoxLayout *verticalLayout3 = new QVBoxLayout;

    QLabel *tokenLabel = new QLabel("<b>TOKEN/ ENCODED</b>");
    QTextEdit *tokenTextEdit = new QTextEdit;
    tokenTextEdit->setAcceptRichText(true);
    tokenTextEdit->setStyleSheet("background-color: #EDF3F8;");

    verticalLayout3->addWidget(tokenLabel);
    verticalLayout3->addWidget(tokenTextEdit);

    // Horizontal Layout for all three vertical layouts
    QHBoxLayout *mainLayout = new QHBoxLayout(&mainWindow);
    mainLayout->addLayout(verticalLayout1);
    mainLayout->addLayout(verticalLayout2);
    mainLayout->addLayout(verticalLayout3);

    // Changing the alg in header according to algo selecting
    //
    QObject::connect(comboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), [&](int index) {
        // Update the header text based on the selected algorithm
        QString algorithm = comboBox->itemText(index);
        QString headerText = QString("{\n    \"alg\": \"%1\",\n    \"typ\": \"JWT\"\n}").arg(algorithm);

        // Set the HTML content with color for header
        QString htmlContent = "<span style='color: red;'><pre style='font-family: inherit;'>" + headerText.toHtmlEscaped() + "</pre></span>";
        headerTextEdit->setHtml(htmlContent);
    });

    // Connect the signal to update the text and color based on the selected algorithm
    QObject::connect(comboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), [&](int index) {
        // Update label9 based on the selected algorithm
        QString algorithm = comboBox->itemText(index);
        QString label9Text = QString("HMACSHA%1(\n  base64UrlEncode(header) + \".\" +\n  base64UrlEncode(payload),")
                                 .arg(algorithm.mid(2)); // Extract the number from the algorithm name
        label9->setText(label9Text);
        //.arg(algorithm.mid(2)) ie ???//
        // Set the text color to blue
        label9->setStyleSheet("color: blue;");
    });

    // Add a slot or lambda function to update the signature based on the checkbox state
    QObject::connect(base64CheckBox, &QCheckBox::stateChanged, [&]() {
        bool secretBase64Encoded = (base64CheckBox->isChecked());
        updateSignature(tokenTextEdit, headerTextEdit, payloadTextEdit, lineEdit->text(), secretBase64Encoded, comboBox->currentText(), base64CheckBox);
    });


    QObject::connect(encodeButton, &QPushButton::clicked, [&]() {
        // Extract header and payload from the GUI
        QJsonObject header = QJsonDocument::fromJson(headerTextEdit->toPlainText().toUtf8()).object();
        QJsonObject payload = QJsonDocument::fromJson(payloadTextEdit->toPlainText().toUtf8()).object();

        // Get the secret key from the GUI
        QString secretKey = lineEdit->text();

        // Generate the JWT token based on the selected algorithm
        QString algorithm = comboBox->currentText();
        QString jwtToken;

        // Check if the algorithm in the header matches the selected algorithm
        if (!isHeaderValid(header, algorithm)) {
            QMessageBox::critical(&mainWindow, "Error", "Algorithm or Typ in header is incorrect.");
            return;
        }
        if (!isValidJson(headerTextEdit->toPlainText()) || !isValidJson(payloadTextEdit->toPlainText())){
            QMessageBox::critical(&mainWindow, "Error", "Invalid JSON format in payload.");
            return;
        }
        if (algorithm == "HS256" || algorithm == "HS384" || algorithm == "HS512") {
            jwtToken = generateJwt(header, payload, secretKey, algorithm, secretBase64Encoded);

            // Set the HTML content with different colors for header, payload, and signature
            QString htmlContent = "<span style='color: red;'>" + base64UrlEncode(QJsonDocument(header).toJson(QJsonDocument::Compact)) + "</span>"
                                                                                                                                         "<span style='color: purple;'>." + base64UrlEncode(QJsonDocument(payload).toJson(QJsonDocument::Compact)) + "</span>"
                                                                                                             "<span style='color: blue;'>." + jwtToken.section('.', 2) + "</span><br>";

            // Display the HTML content in the QLabel
            tokenTextEdit->setHtml(htmlContent);
        }

    });

    // Inside the decodeButton connection block
    QObject::connect(decodeButton, &QPushButton::clicked, [&]() {
        // Get the JWT and secret key from the GUI
        QString jwtToken = tokenTextEdit->toPlainText();
        QString secretKey = lineEdit->text();

        // Check if the JWT token is empty
        if (jwtToken.isEmpty()) {
            QMessageBox::critical(&mainWindow, "Error", "Please enter a JWT token for decoding.");
            return;
        }
        QStringList parts = jwtToken.split('.');
        // Check if the JWT token has the expected three parts
        if (parts.size() != 3) {
            QMessageBox::critical(&mainWindow, "Error", "Invalid token");
            return;
        }

        QString decodedAlgorithm;
        QJsonObject result = decodeJwt(jwtToken, secretKey, decodedAlgorithm, comboBox, tokenTextEdit, secretBase64Encoded);

        // Verify the JWT signature
        bool signatureValid = verifyJwtSignature(jwtToken, secretKey, decodedAlgorithm, secretBase64Encoded);
        if (!signatureValid) {
            // Set the HTML content with different colors for header and payload
            QString headerHtmlContent = "<span style='color: red;'><pre style='font-family: inherit;'>" + QString(QJsonDocument(result["header"].toObject()).toJson(QJsonDocument::Indented)).toHtmlEscaped() + "</pre></span>";
            QString payloadHtmlContent = "<span style='color: purple;'><pre style='font-family: inherit;'>" + QString(QJsonDocument(result["payload"].toObject()).toJson(QJsonDocument::Indented)).toHtmlEscaped() + "</pre></span>";

            // Display the HTML content in the corresponding QTextEdits or other suitable widgets
            headerTextEdit->setHtml(headerHtmlContent);
            payloadTextEdit->setHtml(payloadHtmlContent);

            // Display the header and payload along with the error message
            QString errorMessage = "Signature verification failed.";
            QMessageBox::critical(&mainWindow, "Error", errorMessage);

            return;
        }
        // Set the combo box to the index corresponding to the decoded algorithm
        int index = comboBox->findText(decodedAlgorithm);
        if (index != -1) {
            comboBox->setCurrentIndex(index);
        } else {
            QMessageBox::warning(&mainWindow, "Warning", "Algorithm not found in the combo box: " + decodedAlgorithm);
        }
        // Set the HTML content with different colors for header and payload
        QString headerHtmlContent = "<span style='color: red;'><pre style='font-family: inherit;'>" + QString(QJsonDocument(result["header"].toObject()).toJson(QJsonDocument::Indented)).toHtmlEscaped() + "</pre></span>";
        QString payloadHtmlContent = "<span style='color: purple;'><pre style='font-family: inherit;'>" + QString(QJsonDocument(result["payload"].toObject()).toJson(QJsonDocument::Indented)).toHtmlEscaped() + "</pre></span>";

        // Display the HTML content in the corresponding QTextEdits or other suitable widgets
        headerTextEdit->setHtml(headerHtmlContent);
        payloadTextEdit->setHtml(payloadHtmlContent);

    });

    QObject::connect(clearButton, &QPushButton::clicked, [&]() {
        // Clear the encoded text
        tokenTextEdit->clear();
    });

    mainWindow.setStyleSheet("background-color: #B9E2FF;");
    mainWindow.show();

    return app.exec();
}
