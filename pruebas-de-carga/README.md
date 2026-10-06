# Pruebas de carga

Tres escenarios en un solo script, [`carga.js`](carga.js), que se eligen con
`ESCENARIO`.

```bash
docker run --rm --network automatizacion-correos_default \
  -v "$PWD/pruebas-de-carga:/carga:ro" \
  -e BASE_URL=http://api:8000 -e ESCENARIO=humo \
  grafana/k6:latest run /carga/carga.js
```

Con k6 instalado en la máquina:

```bash
k6 run --env BASE_URL=http://localhost:8000 --env ESCENARIO=humo pruebas-de-carga/carga.js
```

| Escenario | Carga | Necesita token | Qué mide |
|-----------|-------|----------------|----------|
| `humo` | 1 VU, 1 iteración | no | Que el servicio responda, que los endpoints protegidos exijan autenticación y que el limitador corte una ráfaga |
| `lectura` | rampa a 20 VUs, 3 min | sí | p95 del listado de registros y de la cola de revisión, incluida la segunda página por cursor |
| `escaneos` | 50 VUs, 1 iteración cada uno | sí | Que la API encole sin degradarse y que la cuota por tenant corte en lugar de dejar crecer la cola |

## Sobre el token

La API verifica la firma del JWT contra el JWKS del proveedor de identidad y
**no tiene ninguna pasarela para entornos de desarrollo**. Es deliberado: una
pasarela así es exactamente la que alguien deja abierta en producción. Los
escenarios autenticados reciben por tanto un access token real:

```bash
k6 run --env ESCENARIO=lectura --env TOKEN="$ACCESS_TOKEN" pruebas-de-carga/carga.js
```

```bash
k6 run --env ESCENARIO=escaneos --env TOKEN="$ACCESS_TOKEN" \
  --env CONEXION_ID="$ID_DEL_BUZON" pruebas-de-carga/carga.js
```

Su sitio natural es **staging**, que es donde las cifras significan algo: medir
en un portátil con la base de datos, Redis, el almacén y la propia API
compitiendo por los mismos núcleos da números que no sirven para dimensionar
nada.

`humo` no necesita token y corre en cualquier sitio.

## Umbrales

Declarados en el propio script, de modo que k6 termina con código distinto de
cero si no se cumplen:

- `http_req_failed < 1 %`, contando como fallo solo los 5xx y los errores de
  red. Un 401 o un 429 son respuestas correctas aquí, y contarlos como fallo
  haría el umbral inútil.
- p95 **< 300 ms** en el listado de registros y en la cola de revisión, que es
  el objetivo del [plan de arquitectura](../ARQUITECTURA.md#14-estrategia-de-testing).
- p95 **< 1 s** al encolar un escaneo: es una escritura barata y no debe
  acercarse al segundo.

## Lo que encontró

El escenario de humo destapó una denegación de servicio sin autenticar. La
cuota horaria de escaneos la aplicaba el middleware de rate limit, que corre
**antes** de autenticar y por tanto solo puede contar por dirección IP: con
veintiuna peticiones anónimas se agotaba la cuota de todos los que
compartieran salida a internet, y quedaban sin poder lanzar escaneos durante
una hora. Sin credenciales de ningún tipo.

Las cuotas se aplican ahora por tenant y después de resolver la identidad
(`limita_por_tenant`), y el middleware ha quedado como lo que podía ser: un
cortafuegos por minuto contra avalanchas. Los tests de
[`tests/security/test_cuotas.py`](../tests/security/test_cuotas.py) lo fijan.

Es un fallo que ningún test podía ver, porque el efecto solo aparece al cruzar
tráfico anónimo con una cuota de negocio bajo concurrencia.
