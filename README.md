Эта система создана для захвата пакетов с помощью tcpdump для домашнего роутера с Xiami MI-MINI 3.4.113 с архитектурой mips GNU/Linux. 

Для корректной работы системы требуется:

Если на роутере есть возможность прошивки OpenWRT установка tcpdump не составит труда, если же перепрошивать не охота:

1. Получаем доступ по ssh к роутеру (обычно можно прокинуть ssh ключи зайдя по адресу роутера в разделе администрирование -> сервисы).
2. Перекидываем на флешку скрипт tcpdump-mt7620.sh и бинарник tcpdump-mt7620
3. Втыкаем флешку в роутер (запуск tcpdump будет именно с нее)
4. В app.py меняем ssh router@ip на необходимый, а также выбираем интерфейс (у меня это br0) и важно изменить путь до скрипта на роутере (у меня это /media/FLASH/tcpdump-mt7620)
5. Запускаем app.py

PS: Бинарник и скрипт собран именно под архитектуру данного роутера: Xiami MI-MINI 3.4.113 mips GNU/Linux
