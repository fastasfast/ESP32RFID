Added to K2-RFID

Added a "Read Card" button that will show "MatchesCurrentSpoolData=" Yes or No. You can be sure your RFID was written to.

Added a "Reset Card Key", will reset RFID in case something goes wrong. Had a couple of RFID's I could not write to.

# ESP32

Default Access point information:<br>
```
SSID:    K2_RFID
PASS:    password
Web URL: http://10.1.0.1 or http://k2.local
```


<br>
Hardware:<br>
<a href=https://en.wikipedia.org/wiki/ESP32>ESP32</a><br>
<a href=https://esphome.io/components/binary_sensor/rc522.html>RC522</a><br>
<br>
<br>
This should work on most ESP32 boards including S2 and S3 variants
<br><br>

GPIO Connections:<br>
<img src=https://github.com/DnG-Crafts/K2-RFID/blob/main/Arduino/ESP32/pins.jpg>
