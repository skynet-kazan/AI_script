Формат сценария (TXT):
1) Секция до "---": параметры подключения (ключ=значение)
   - device_type = тип Netmiko (cisco_ios, huawei, linux, juniper_junos и т.д.)
   - username = логин SSH
   - password = пароль SSH
2) После "---": по одной команде на строку.

В командах можно использовать плейсхолдеры:
  {model}         — модель оборудования
  {equipment_ip}  — IP оборудования
  {client_ip}     — IP клиента
  {vlan}          — VLAN клиента
  {port}          — порт на оборудовании

Имя файла сценария = имя модели (например cisco_ios.txt для model=cisco_ios).
