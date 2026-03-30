#include <FS.h>
#include <SPI.h>
#include <WiFi.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>
#include <LittleFS.h>
#include <esp_system.h>
#include "src/includes.h"

#define SS_PIN 5
#define RST_PIN 21
#define SPK_PIN 27

MFRC522 mfrc522(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;
MFRC522::MIFARE_Key ekey;
WebServer webServer(80);
AES aes;
File upFile;
String upMsg;
MD5Builder md5;

IPAddress Server_IP(10, 1, 0, 1);
IPAddress Subnet_Mask(255, 255, 255, 0);
String spoolData = "AB1240276A210100100000FF016500000100000000000000";
String AP_SSID = "K2_RFID";
String AP_PASS = "password";
String WIFI_SSID = "";
String WIFI_PASS = "";
String WIFI_HOSTNAME = "k2.local";
String PRINTER_HOSTNAME = "";
bool encrypted = false;
bool resetMode = false;

String byteToHex(byte value)
{
  const char hexChars[] = "0123456789ABCDEF";
  String out = "";
  out += hexChars[(value >> 4) & 0x0F];
  out += hexChars[value & 0x0F];
  return out;
}

String bytesToHex(const byte *data, byte len)
{
  String out = "";
  for (byte i = 0; i < len; i++)
  {
    out += byteToHex(data[i]);
  }
  return out;
}


void setup()
{
  Serial.begin(115200);
  LittleFS.begin(true);
  loadConfig();
  randomSeed(static_cast<uint32_t>(esp_random()));
  SPI.begin();
  mfrc522.PCD_Init();
  key = {255, 255, 255, 255, 255, 255};
  pinMode(SPK_PIN, OUTPUT);
  if (AP_SSID == "" || AP_PASS == "")
  {
    AP_SSID = "K2_RFID";
    AP_PASS = "password";
  }
  WiFi.softAPConfig(Server_IP, Server_IP, Subnet_Mask);
  WiFi.softAP(AP_SSID.c_str(), AP_PASS.c_str());
  WiFi.softAPConfig(Server_IP, Server_IP, Subnet_Mask);

  if (WIFI_SSID != "" && WIFI_PASS != "")
  {
    WiFi.setAutoReconnect(true);
    WiFi.hostname(WIFI_HOSTNAME);
    WiFi.begin(WIFI_SSID.c_str(), WIFI_PASS.c_str());
    if (WiFi.waitForConnectResult() == WL_CONNECTED)
    {
      IPAddress LAN_IP = WiFi.localIP();
    }
  }
  if (WIFI_HOSTNAME != "")
  {
    String mdnsHost = WIFI_HOSTNAME;
    mdnsHost.replace(".local", "");
    MDNS.begin(mdnsHost.c_str());
  }

  webServer.on("/config", HTTP_GET, handleConfig);
  webServer.on("/index.html", HTTP_GET, handleIndex);
  webServer.on("/", HTTP_GET, handleIndex);
  webServer.on("/material_database.json", HTTP_GET, handleDb);
  webServer.on("/config", HTTP_POST, handleConfigP);
  webServer.on("/spooldata", HTTP_POST, handleSpoolData);
  webServer.on("/resetcard", HTTP_POST, handleResetCard);
  webServer.on("/readcard", HTTP_POST, handleReadCard);
  webServer.on("/update.html", HTTP_POST, []() {
    webServer.send(200, "text/plain", upMsg);
    delay(1000);
    ESP.restart();
  }, []() {
    handleFwUpdate();
  });
  webServer.on("/updatedb.html", HTTP_POST, []() {
    webServer.send(200, "text/plain", upMsg);
    delay(1000);
    ESP.restart();
  }, []() {
    handleDbUpdate();
  });
  webServer.onNotFound(handle404);
  webServer.begin();
  Serial.println("[BOOT] AP: " + AP_SSID + "  WIFI: " + (WIFI_SSID.isEmpty() ? "(none)" : WIFI_SSID));
  Serial.println("[BOOT] Web server started");
}


void loop()
{
  webServer.handleClient();
  if (!mfrc522.PICC_IsNewCardPresent())
    return;

  if (!mfrc522.PICC_ReadCardSerial())
    return;

  if (resetMode)
  {
    resetMode = false;
    String uidStr = "";
    for (byte i = 0; i < mfrc522.uid.size; i++) {
      if (mfrc522.uid.uidByte[i] < 0x10) uidStr += "0";
      uidStr += String(mfrc522.uid.uidByte[i], HEX);
    }
    uidStr.toUpperCase();
    Serial.println("[RESET] Card UID: " + uidStr);
    createKey();
    MFRC522::StatusCode status;
    status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &ekey, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK)
    {
      Serial.println("[RESET] Auth failed: " + String(mfrc522.GetStatusCodeName(status)));
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();
      tone(SPK_PIN, 400, 150); delay(300); tone(SPK_PIN, 400, 150); delay(2000);
      return;
    }
    byte buffer[18];
    byte byteCount = sizeof(buffer);
    status = mfrc522.MIFARE_Read(7, buffer, &byteCount);
    if (status != MFRC522::STATUS_OK)
    {
      Serial.println("[RESET] Trailer read failed: " + String(mfrc522.GetStatusCodeName(status)));
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();
      tone(SPK_PIN, 400, 150); delay(300); tone(SPK_PIN, 400, 150); delay(2000);
      return;
    }
    // Restore Key A and Key B to factory default (FF FF FF FF FF FF)
    for (int i = 0; i < 6; i++)  buffer[i]      = 0xFF;
    for (int i = 10; i < 16; i++) buffer[i]     = 0xFF;
    status = (MFRC522::StatusCode)mfrc522.MIFARE_Write(7, buffer, 16);
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    if (status != MFRC522::STATUS_OK)
    {
      Serial.println("[RESET] Trailer write failed: " + String(mfrc522.GetStatusCodeName(status)));
      tone(SPK_PIN, 400, 150); delay(300); tone(SPK_PIN, 400, 150); delay(2000);
    }
    else
    {
      Serial.println("[RESET] Key restored to factory default");
      tone(SPK_PIN, 1000, 100); delay(150); tone(SPK_PIN, 1000, 100); delay(150); tone(SPK_PIN, 1000, 100);
      delay(2000);
    }
    return;
  }

  encrypted = false;

  // Print UID
  String uidStr = "";
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    if (mfrc522.uid.uidByte[i] < 0x10) uidStr += "0";
    uidStr += String(mfrc522.uid.uidByte[i], HEX);
  }
  uidStr.toUpperCase();
  Serial.println("[CARD] UID: " + uidStr);

  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI && piccType != MFRC522::PICC_TYPE_MIFARE_1K && piccType != MFRC522::PICC_TYPE_MIFARE_4K)
  {
    Serial.println("[CARD] Unsupported card type: " + String(mfrc522.PICC_GetTypeName(piccType)));
    tone(SPK_PIN, 400, 400);
    delay(2000);
    return;
  }
  Serial.println("[CARD] Type: " + String(mfrc522.PICC_GetTypeName(piccType)));

  createKey();

  MFRC522::StatusCode status;
  status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK)
  {
      mfrc522.PCD_StopCrypto1(); // clear RC522 crypto state before retry
      Serial.println("[AUTH] Default key failed, trying derived key");
      // Failed auth returns card to IDLE — must reselect before second attempt
      if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial())
      {
        Serial.println("[AUTH] Card lost after first auth failure");
        mfrc522.PCD_StopCrypto1();
        tone(SPK_PIN, 400, 150);
        delay(300);
        tone(SPK_PIN, 400, 150);
        delay(2000);
        return;
      }
      status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &ekey, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK)
    {
      Serial.println("[AUTH] Both keys failed: " + String(mfrc522.GetStatusCodeName(status)));
        mfrc522.PICC_HaltA();
        mfrc522.PCD_StopCrypto1();
      tone(SPK_PIN, 400, 150);
      delay(300);
      tone(SPK_PIN, 400, 150);
      delay(2000);
      return;
    }
    encrypted = true;
    Serial.println("[AUTH] Authenticated with derived key (card already encrypted)");
  }
  else
  {
    Serial.println("[AUTH] Authenticated with default key");
  }

  if (spoolData.length() != 48)
  {
    Serial.println("[DATA] Invalid spool data length: " + String(spoolData.length()) + " (expected 48)");
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    tone(SPK_PIN, 400, 150);
    delay(300);
    tone(SPK_PIN, 400, 150);
    delay(2000);
    return;
  }
  Serial.println("[DATA] Writing spool data: " + spoolData);

  byte blockData[17];
  byte encData[16];
  int blockID = 4;
  bool writeFailed = false;
  for (int i = 0; i < spoolData.length(); i += 16)
  {
    spoolData.substring(i, i + 16).getBytes(blockData, 17);
    if (blockID >= 4 && blockID < 7)
    {
      aes.encrypt(1, blockData, encData);
      status = (MFRC522::StatusCode)mfrc522.MIFARE_Write(blockID, encData, 16);
      if (status != MFRC522::STATUS_OK)
      {
        Serial.println("[WRITE] Block " + String(blockID) + " failed: " + String(mfrc522.GetStatusCodeName(status)));
        writeFailed = true;
        break;
      }
      Serial.println("[WRITE] Block " + String(blockID) + " OK");
    }
    blockID++;
  }

  if (!encrypted && !writeFailed)
  {
    byte buffer[18];
    byte byteCount = sizeof(buffer);
    byte block = 7;
    status = mfrc522.MIFARE_Read(block, buffer, &byteCount);
    if (status != MFRC522::STATUS_OK)
    {
      Serial.println("[WRITE] Sector trailer read failed: " + String(mfrc522.GetStatusCodeName(status)));
      writeFailed = true;
    }
    else
    {
      int y = 0;
      for (int i = 10; i < 16; i++)
      {
        buffer[i] = ekey.keyByte[y];
        y++;
      }
      for (int i = 0; i < 6; i++)
      {
        buffer[i] = ekey.keyByte[i];
      }
      status = (MFRC522::StatusCode)mfrc522.MIFARE_Write(7, buffer, 16);
      if (status != MFRC522::STATUS_OK)
      {
        Serial.println("[WRITE] Sector trailer write failed: " + String(mfrc522.GetStatusCodeName(status)));
        writeFailed = true;
      }
      else
      {
        Serial.println("[WRITE] Sector trailer updated with new key");
      }
    }
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
  if (writeFailed)
  {
    Serial.println("[RESULT] FAILED");
    tone(SPK_PIN, 400, 150);
    delay(300);
    tone(SPK_PIN, 400, 150);
    delay(2000);
    return;
  }
  Serial.println("[RESULT] SUCCESS");
  tone(SPK_PIN, 1000, 200);
  delay(2000);
}

void createKey()
{
  int x = 0;
  byte uid[16];
  byte bufOut[16];
  for (int i = 0; i < 16; i++)
  {
    if (x >= 4)
      x = 0;
    uid[i] = mfrc522.uid.uidByte[x];
    x++;
  }
  aes.encrypt(0, uid, bufOut);
  for (int i = 0; i < 6; i++)
  {
    ekey.keyByte[i] = bufOut[i];
  }
}

void handleResetCard()
{
  resetMode = true;
  Serial.println("[RESET] Reset mode active — present card to restore factory key");
  webServer.send(200, "text/plain", "Reset mode active. Present the card to the reader.");
}

void handleReadCard()
{
  unsigned long timeoutAt = millis() + 8000;
  while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial())
  {
    if (millis() > timeoutAt)
    {
      webServer.send(408, "text/plain", "No card detected. Hold card on reader and try again.");
      return;
    }
    delay(50);
  }

  String uidStr = "";
  for (byte i = 0; i < mfrc522.uid.size; i++)
  {
    uidStr += byteToHex(mfrc522.uid.uidByte[i]);
  }

  createKey();
  MFRC522::StatusCode status;
  bool usedDerivedKey = false;
  status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &key, &(mfrc522.uid));

  if (status != MFRC522::STATUS_OK)
  {
    mfrc522.PCD_StopCrypto1();
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial())
    {
      webServer.send(401, "text/plain", "Auth failed and card was lost before retry.");
      return;
    }
    status = (MFRC522::StatusCode)mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_A, 7, &ekey, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK)
    {
      String msg = "Read auth failed: ";
      msg += mfrc522.GetStatusCodeName(status);
      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();
      webServer.send(401, "text/plain", msg);
      return;
    }
    usedDerivedKey = true;
  }

  byte block4[18];
  byte block5[18];
  byte block6[18];
  byte byteCount = 18;
  status = mfrc522.MIFARE_Read(4, block4, &byteCount);
  if (status != MFRC522::STATUS_OK)
  {
    String msg = "Read block 4 failed: ";
    msg += mfrc522.GetStatusCodeName(status);
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    webServer.send(500, "text/plain", msg);
    return;
  }
  byteCount = 18;
  status = mfrc522.MIFARE_Read(5, block5, &byteCount);
  if (status != MFRC522::STATUS_OK)
  {
    String msg = "Read block 5 failed: ";
    msg += mfrc522.GetStatusCodeName(status);
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    webServer.send(500, "text/plain", msg);
    return;
  }
  byteCount = 18;
  status = mfrc522.MIFARE_Read(6, block6, &byteCount);
  if (status != MFRC522::STATUS_OK)
  {
    String msg = "Read block 6 failed: ";
    msg += mfrc522.GetStatusCodeName(status);
    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
    webServer.send(500, "text/plain", msg);
    return;
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  byte expected4[16];
  byte expected5[16];
  byte expected6[16];
  byte blockData[17];
  spoolData.substring(0, 16).getBytes(blockData, 17);
  aes.encrypt(1, blockData, expected4);
  spoolData.substring(16, 32).getBytes(blockData, 17);
  aes.encrypt(1, blockData, expected5);
  spoolData.substring(32, 48).getBytes(blockData, 17);
  aes.encrypt(1, blockData, expected6);

  bool block4Match = true;
  bool block5Match = true;
  bool block6Match = true;
  for (int i = 0; i < 16; i++)
  {
    if (block4[i] != expected4[i]) block4Match = false;
    if (block5[i] != expected5[i]) block5Match = false;
    if (block6[i] != expected6[i]) block6Match = false;
  }

  String readout = "UID=" + uidStr + "\n";
  readout += "AuthKey=" + String(usedDerivedKey ? "DERIVED" : "DEFAULT") + "\n";
  readout += "Block4=" + bytesToHex(block4, 16) + "\n";
  readout += "Block5=" + bytesToHex(block5, 16) + "\n";
  readout += "Block6=" + bytesToHex(block6, 16) + "\n";
  readout += "ExpectedSpoolData=" + spoolData + "\n";
  readout += "MatchesCurrentSpoolData=" + String((block4Match && block5Match && block6Match) ? "YES" : "NO");

  Serial.println("[READ] UID: " + uidStr + " Match: " + String((block4Match && block5Match && block6Match) ? "YES" : "NO"));
  webServer.send(200, "text/plain", readout);
}

void handleIndex()
{
  webServer.send_P(200, "text/html", indexData);
}

void handle404()
{
  webServer.send(404, "text/plain", "Not Found");
}

void handleConfig()
{
  String htmStr = AP_SSID + "|-|" + WIFI_SSID + "|-|" + WIFI_HOSTNAME + "|-|" + PRINTER_HOSTNAME;
  webServer.setContentLength(htmStr.length());
  webServer.send(200, "text/plain", htmStr);
}

void handleConfigP()
{
  if (webServer.hasArg("ap_ssid") && webServer.hasArg("ap_pass") && webServer.hasArg("wifi_ssid") && webServer.hasArg("wifi_pass") && webServer.hasArg("wifi_host") && webServer.hasArg("printer_host"))
  {
    AP_SSID = webServer.arg("ap_ssid");
    if (!webServer.arg("ap_pass").equals("********"))
    {
      AP_PASS = webServer.arg("ap_pass");
    }
    WIFI_SSID = webServer.arg("wifi_ssid");
    if (!webServer.arg("wifi_pass").equals("********"))
    {
      WIFI_PASS = webServer.arg("wifi_pass");
    }
    WIFI_HOSTNAME = webServer.arg("wifi_host");
    PRINTER_HOSTNAME = webServer.arg("printer_host");
    File file = LittleFS.open("/config.ini", "w");
    if (file)
    {
      file.print("\r\nAP_SSID=" + AP_SSID + "\r\nAP_PASS=" + AP_PASS + "\r\nWIFI_SSID=" + WIFI_SSID + "\r\nWIFI_PASS=" + WIFI_PASS + "\r\nWIFI_HOST=" + WIFI_HOSTNAME + "\r\nPRINTER_HOST=" + PRINTER_HOSTNAME + "\r\n");
      file.close();
    }
    String htmStr = "OK";
    webServer.setContentLength(htmStr.length());
    webServer.send(200, "text/plain", htmStr);
    delay(1000);
    ESP.restart();
  }
  else
  {
    webServer.send(417, "text/plain", "Expectation Failed");
  }
}

void handleDb()
{
  File dataFile = LittleFS.open("/matdb.gz", "r");
  if (!dataFile) {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.send_P(200, "application/json", material_database, sizeof(material_database));
  }
  else
  {
    webServer.sendHeader("Content-Encoding", "gzip");
    webServer.streamFile(dataFile, "application/json");
    dataFile.close();
  }
}

void handleDbUpdate()
{
  upMsg = "";
  if (webServer.uri() != "/updatedb.html") {
    upMsg = "Error";
    return;
  }
  HTTPUpload &upload = webServer.upload();
  if (upload.filename != "material_database.json") {
    upMsg = "Invalid database file<br><br>" + upload.filename;
    return;
  }
  if (upload.status == UPLOAD_FILE_START) {
    if (LittleFS.exists("/matdb.gz")) {
      LittleFS.remove("/matdb.gz");
    }
    upFile = LittleFS.open("/matdb.gz", "w");
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (upFile) {
      upFile.write(upload.buf, upload.currentSize);
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (upFile) {
      upFile.close();
      upMsg = "Database update complete, Rebooting";
    }
  }
}

void handleFwUpdate()
{
  upMsg = "";
  if (webServer.uri() != "/update.html") {
    upMsg = "Error";
    return;
  }
  HTTPUpload &upload = webServer.upload();
  if (!upload.filename.endsWith(".bin")) {
    upMsg = "Invalid update file<br><br>" + upload.filename;
    return;
  }
  if (upload.status == UPLOAD_FILE_START) {
    if (LittleFS.exists("/update.bin")) {
      LittleFS.remove("/update.bin");
    }
    upFile = LittleFS.open("/update.bin", "w");
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (upFile) {
      upFile.write(upload.buf, upload.currentSize);
    }
  } else if (upload.status == UPLOAD_FILE_END) {
    if (upFile) {
      upFile.close();
    }
    updateFw();
  }
}

void updateFw()
{
  if (LittleFS.exists("/update.bin")) {
    File updateFile;
    updateFile = LittleFS.open("/update.bin", "r");
    if (updateFile) {
      size_t updateSize = updateFile.size();
      if (updateSize > 0) {
        md5.begin();
        md5.addStream(updateFile, updateSize);
        md5.calculate();
        String md5Hash = md5.toString();
        updateFile.close();
        updateFile = LittleFS.open("/update.bin", "r");
        if (updateFile) {
          uint32_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
          if (!Update.begin(maxSketchSpace, U_FLASH)) {
            updateFile.close();
            upMsg = "Update failed<br><br>" + errorMsg(Update.getError());
            return;
          }
          int md5BufSize = md5Hash.length() + 1;
          char md5Buf[md5BufSize];
          md5Hash.toCharArray(md5Buf, md5BufSize) ;
          Update.setMD5(md5Buf);
          long bsent = 0;
          int cprog = 0;
          while (updateFile.available()) {
            uint8_t ibuffer[1];
            updateFile.read((uint8_t *)ibuffer, 1);
            Update.write(ibuffer, sizeof(ibuffer));
            bsent++;
            int progr = ((double)bsent /  updateSize) * 100;
            if (progr >= cprog) {
              cprog = progr + 10;
            }
          }
          updateFile.close();
          LittleFS.remove("/update.bin");
          if (Update.end(true))
          {
            String uHash = md5Hash.substring(0, 10);
            String iHash = Update.md5String().substring(0, 10);
            iHash.toUpperCase();
            uHash.toUpperCase();
            upMsg = "Uploaded:&nbsp; " + uHash + "<br>Installed: " + iHash + "<br><br>Update complete, Rebooting";
          }
          else
          {
            upMsg = "Update failed";
          }
        }
      }
      else {
        updateFile.close();
        LittleFS.remove("/update.bin");
        upMsg = "Error, file is invalid";
        return;
      }
    }
  }
  else
  {
    upMsg = "No update file found";
  }
}

void handleSpoolData()
{
  if (webServer.hasArg("materialColor") && webServer.hasArg("materialType") && webServer.hasArg("materialWeight"))
  {
    String materialColor = webServer.arg("materialColor");
    materialColor.replace("#", "");
    String filamentId = "1" + webServer.arg("materialType"); // material_database.json
    String vendorId = "0276"; // 0276 creality
    String color = "0" + materialColor;
    String filamentLen = GetMaterialLength(webServer.arg("materialWeight"));
    String serialNum = String(random(100000, 999999)); // 000001
    String reserve = "000000";
    spoolData = "AB124" + vendorId + "A2" + filamentId + color + filamentLen + serialNum + reserve + "00000000";
    File file = LittleFS.open("/spool.ini", "w");
    if (file)
    {
      file.print(spoolData);
      file.close();
    }
    String htmStr = "OK";
    webServer.setContentLength(htmStr.length());
    webServer.send(200, "text/plain", htmStr);
  }
  else
  {
    webServer.send(417, "text/plain", "Expectation Failed");
  }
}

String GetMaterialLength(String materialWeight)
{
  if (materialWeight == "1 KG")
  {
    return "0330";
  }
  else if (materialWeight == "750 G")
  {
    return "0247";
  }
  else if (materialWeight == "600 G")
  {
    return "0198";
  }
  else if (materialWeight == "500 G")
  {
    return "0165";
  }
  else if (materialWeight == "250 G")
  {
    return "0082";
  }
  return "0330";
}

String errorMsg(int errnum)
{
  if (errnum == UPDATE_ERROR_OK) {
    return "No Error";
  } else if (errnum == UPDATE_ERROR_WRITE) {
    return "Flash Write Failed";
  } else if (errnum == UPDATE_ERROR_ERASE) {
    return "Flash Erase Failed";
  } else if (errnum == UPDATE_ERROR_READ) {
    return "Flash Read Failed";
  } else if (errnum == UPDATE_ERROR_SPACE) {
    return "Not Enough Space";
  } else if (errnum == UPDATE_ERROR_SIZE) {
    return "Bad Size Given";
  } else if (errnum == UPDATE_ERROR_STREAM) {
    return "Stream Read Timeout";
  } else if (errnum == UPDATE_ERROR_MD5) {
    return "MD5 Check Failed";
  } else if (errnum == UPDATE_ERROR_MAGIC_BYTE) {
    return "Magic byte is wrong, not 0xE9";
  } else {
    return "UNKNOWN";
  }
}

void loadConfig()
{
  if (LittleFS.exists("/config.ini"))
  {
    File file = LittleFS.open("/config.ini", "r");
    if (file)
    {
      String iniData;
      while (file.available())
      {
        char chnk = file.read();
        iniData += chnk;
      }
      file.close();
      if (instr(iniData, "AP_SSID="))
      {
        AP_SSID = split(iniData, "AP_SSID=", "\r\n");
        AP_SSID.trim();
      }

      if (instr(iniData, "AP_PASS="))
      {
        AP_PASS = split(iniData, "AP_PASS=", "\r\n");
        AP_PASS.trim();
      }

      if (instr(iniData, "WIFI_SSID="))
      {
        WIFI_SSID = split(iniData, "WIFI_SSID=", "\r\n");
        WIFI_SSID.trim();
      }

      if (instr(iniData, "WIFI_PASS="))
      {
        WIFI_PASS = split(iniData, "WIFI_PASS=", "\r\n");
        WIFI_PASS.trim();
      }

      if (instr(iniData, "WIFI_HOST="))
      {
        WIFI_HOSTNAME = split(iniData, "WIFI_HOST=", "\r\n");
        WIFI_HOSTNAME.trim();
      }

      if (instr(iniData, "PRINTER_HOST="))
      {
        PRINTER_HOSTNAME = split(iniData, "PRINTER_HOST=", "\r\n");
        PRINTER_HOSTNAME.trim();
      }
      
    }
  }
  else
  {
    File file = LittleFS.open("/config.ini", "w");
    if (file)
    {
      file.print("\r\nAP_SSID=" + AP_SSID + "\r\nAP_PASS=" + AP_PASS + "\r\nWIFI_SSID=" + WIFI_SSID + "\r\nWIFI_PASS=" + WIFI_PASS + "\r\nWIFI_HOST=" + WIFI_HOSTNAME + "\r\nPRINTER_HOST=" + PRINTER_HOSTNAME + "\r\n");
      file.close();
    }
  }

  if (LittleFS.exists("/spool.ini"))
  {
    File file = LittleFS.open("/spool.ini", "r");
    if (file)
    {
      String iniData;
      while (file.available())
      {
        char chnk = file.read();
        iniData += chnk;
      }
      file.close();
      spoolData = iniData;
    }
  }
  else
  {
    File file = LittleFS.open("/spool.ini", "w");
    if (file)
    {
      file.print(spoolData);
      file.close();
    }
  }
}

String split(String str, String from, String to)
{
  String tmpstr = str;
  tmpstr.toLowerCase();
  from.toLowerCase();
  to.toLowerCase();
  int pos1 = tmpstr.indexOf(from);
  int pos2 = tmpstr.indexOf(to, pos1 + from.length());
  String retval = str.substring(pos1 + from.length(), pos2);
  return retval;
}

bool instr(String str, String search)
{
  int result = str.indexOf(search);
  if (result == -1)
  {
    return false;
  }
  return true;
}
