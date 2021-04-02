   1.	Динамически подключаемая библиотека, предоставляющая интерфейс для работы с (3,5)-пороговой схемой
   разделения секрета Шамира.
        Процесс сборки представлен здесь https://travis-ci.org/github/avduckart/ShamirSecretSharing

   2.	Функция construct_polynom генерирует полином 2-й степени для реализации схемы разделения Шамира. Свободный
   член этого полинома и есть секрет, подлежащий разделению.

   3.	Функция destruct_polynom освобождает память, выделенную для хранения значений коэффициентов полинома.
   
   4.	Функция share_secret осуществляет все необходимые вычисления для разделения секрета - свободного члена 
   полинома - на  5 частей, 3 из которых однозначно его восстанавливают. Для значений от 1 до 5 вычисляется 
   значение полинома - тень. Часть секрета представляет собой пару индекс-тень.
        Вычисление производится в 3 потока. Прежде вычислений значения частей содержат тени со значением 0.
     - В потоке, выполняющем функцию calc_a0, каждой из 5 теней прибавляется значение свободного члена.
     - В потоке, выполняющем функцию calc_a1, происходит вычисление значения монома с коэффициентом a1 и сложение с 
    текущим значением каждой из теней.
     - В потоке, выполняющем функцию calc_a2, происходит вычисление значения монома с коэффициентом a2 и сложение с 
    текущим значением каждой из теней.
        Вычисление теней выполнено без использования дорогостоящих по времени операций умножения и возведения в 
    степень в конечной мультипликативной группе.

   5.	Функция restore_secret осуществляет все необходимые вычисления для восстановления секрета.
        Вычисление производится в 3 потока. В каждом потоке выполняется функция calc_term. Прежде вычислений 
    происходит подготовка различный входных данных для каждого потока. Каждый набор данных содержит адрес секрета, 
    по которому лежит 0.
        В каждом потоке происходит вычисление свободного члена каждого базисного полинома Лагранжа для каждой 
    части, умножение его на соответствующий коэффициент полинома и сложение полученного значения с текущим 
    значением секрета.

   6.	Тип polynom_t является массивом из 3х указателей на значения типа BIGNUM.

   7.	Тип part_t является структурой, содержащей адреса значений индекса и тени.

   8.	Тип share_data_t является структурой, содержащей адрес частей, коэффициентов полинома, значения модуля 
    полинома, а также результат выполнения текущего этапа разделения секрета и значения мьютекса, необходимого для 
    разделения доступа к изменению текущего значения тени.

   9.	Тип restore_data_t является структурой, содержащей адрес, по которому будет записан секрет, адрес 
    частей, адрес модуля полоинома, адрес единого для всех потоков мьютекса, необходимого для разделения доступа
    к изменению текущего значения секрета, а также результат выполнения текущего этапа восстановления секрета.

   10.	В папке sample представлен пример взаимодействия собранной динамической библиотеки с интерфейсом 
    Microsoft CryptoAPI 2.0:
        1. Средствами wincrypto генерируется симметричный ключ шифрования К;
        2. Средствами представляемой библиотеки генерируется ключ МК (master key) для зашифрования ключа К;
        3. Импорт ключа МК по схеме MK' = H(MK);
        4. Разделение ключа МК на 5 частей;
        5. Экспорт ключа K в открытом виде, импорт этого же ключа из памяти по схеме 
            K' = H(H(Padd1^H(K)) || H(Padd2^H(K)));
        6. Зашифрование области памяти, содержащей ключ К ключом MK';
        7. Уничтожение ключа MK';
        8. Зашифрование открытого текста M с помощью ключа K', получение шифртекста C;
        9. Уничтожение ключа K';
        10. Восстановление из 3х чстей ключа MKr (r - restore);
        11. Импорт ключа МКr как в п.3 -> MK'r;
        12. Уничтожение ключа MKr;
        13. Расшифрование с помощью MK'r зашифрованного ранее ключа K;
        14. Импорт расшифрованного ключа K из памяти по схеме Kr' = H(H(Padd1^H(K)) || H(Padd2^H(K)));
        15. Уничтожение ключа MK'r;
        16. Расшифрование шифртекста C с помощью ключа Kr', получение открытого текста M';
        17. Уничтожение ключа Kr';
        18. Сравнение открытых текстов M и M'ю
