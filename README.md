Сборка:

```bash 
g++ main.cpp funcs.hpp objects.hpp -o cringedns --std=c++23
```



Запуск:
```bash
./cringedns <файл конфигурации>
```
Если не указан, используется config.txt


Тестировалось методом `dig @127.0.0.1 -p 29531 vk.com`

*Приношу искренние извинения за свой код.*