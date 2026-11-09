# FLICKER VPN v5.5.14

[![Test Status](https://github.com/zaz131306/FLICKER-VPN-5.5.14-FULL/actions/workflows/test.yml/badge.svg)](https://github.com/zaz131306/FLICKER-VPN-5.5.14-FULL/actions/workflows/test.yml)

Стабильный релиз VPN-расширения (extension v5.5.14 / native host v5.5.4) с закрытыми дефектами локальных транспортов, улучшенным контролем «мёртвых» портов и мгновенным детектированием неработающих нод.

## Проверка тестов (CI / Local)

Для запуска полного набора тестов (111 юнит-тестов + 21 регрессионный сценарный тест) выполните:

```bash
node --test tests/ && node --test regression/src/flicker-vpn/tests/js/
