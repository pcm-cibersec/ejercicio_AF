# Parser general de capturas PCAP/PCAPNG

El script resume una captura y muestra paquetes que Wireshark/TShark reconoce como HTTP. 

## Requisitos e instalación

1. Instala Python 3.
2. Instala Wireshark, que incluye `tshark`, y asegúrate de que `tshark` esté disponible en el `PATH`.
3. Instala PyShark:

```bash
python -m pip install pyshark
```

En algunos sistemas el comando de Python es `python3`:

```bash
python3 -m pip install pyshark
```

## Uso

```bash
python pcap_http_parser.py captura.pcap
python pcap_http_parser.py captura.pcapng
```

Por defecto, la salida muestra peticiones y respuestas HTTP (excepto las respuestas `204 No Content`, que se omiten porque no tienen cuerpo). Con `-m`, muestra solo peticiones que contienen un método HTTP, como GET, POST o PUT. Termina con el número de peticiones mostradas y el resumen general: total de paquetes, conteo por protocolo (un paquete puede contar para varias capas) y duración entre la primera y última marca temporal. Las peticiones muestran método, URI/query, Host y User-Agent; las respuestas se etiquetan con su código HTTP. Para cuerpos HTTP disponibles, la salida normal muestra tipo y tamaño, sin imprimir el contenido completo.

Para mostrar una vista previa (máximo 500 caracteres) del body, ejecuta:

```bash
python pcap_http_parser.py captura.pcap --content
```

Para filtrar las respuestas y mostrar solo peticiones con método:

```bash
python pcap_http_parser.py captura.pcap -m
```

Para añadir un informe de las IP únicas que aparecen en comunicaciones HTTP y el Host asociado a la IP destino cuando se observa en una petición:

```bash
python pcap_http_parser.py captura.pcap --ip
```

Puede combinarse con `-m` y `--mostrar-contenido`. Las IPs para las que la captura no permite asociar un Host aparecen como `(Host no observado)`.

Para filtrar peticiones `POST`, `PUT` y `PATCH` cuyo cuerpo mida al menos 10 KiB:

```bash
python pcap_http_parser.py captura.pcap --POST
```

El tamaño se calcula a partir del cuerpo que TShark logra exponer; si no está disponible, se usa el `Content-Length` declarado cuando aparece en la captura. Por ello, el filtro puede no identificar una carga si la captura está incompleta o no contiene ninguno de esos datos.

Para filtrar peticiones GET con URI de 250 caracteres o más, query de 200 caracteres o más, o valores de parámetros con codificación URL significativa o un token largo compatible con Base64:

```bash
python pcap_http_parser.py captura.pcap --GET
```

El script indica qué criterio hizo coincidir cada URI. Para la codificación URL exige al menos tres escapes `%xx` y que representen al menos el 20 % del valor del parámetro; también marca valores completos compatibles con Base64 de 40 caracteres o más, incluso si aparecen como un elemento de query sin nombre (`?cadena==`). Son heurísticas y pueden producir falsos positivos. `--GET` y `--upload` son alternativas entre sí, pero `--host` sí se puede combinar con cualquiera de ellos. Los filtros combinados se aplican a la vez.

Para filtrar peticiones con Host ausente, Host formado por una IP o subdominio largo:

```bash
python pcap_http_parser.py captura.pcap --host
```

Se considera atípico un subdominio de 30 caracteres o más, un Host completo de 100 caracteres o más, o tres o más niveles de subdominio (estimados tomando las dos últimas etiquetas como dominio y sufijo). El informe explica el motivo por el que cada petición coincide. Es una señal orientativa, no una prueba de actividad maliciosa.

Ejemplo: buscar GET con URI/query llamativa y además un Host atípico:

```bash
python pcap_http_parser.py captura.pcap --GET --host
```

También se puede combinar el filtro de Host con cargas grandes:

```bash
python pcap_http_parser.py captura.pcap --POST --host
```

Para añadir un informe de peticiones por Host y volumen de tráfico TCP asociado a flujos HTTP:

```bash
python pcap_http_parser.py captura.pcap --volume
```

El informe cuenta peticiones por Host y agrupa por IP destino los bytes de payload TCP enviados y recibidos en flujos que contienen peticiones HTTP, junto con la relación salida/entrada. No son bytes exactos del cuerpo HTTP: puede incluir otros datos TCP del flujo y contar retransmisiones. El informe resume los flujos HTTP reconocidos en toda la captura, aunque se combine con otros filtros para la lista de paquetes.


