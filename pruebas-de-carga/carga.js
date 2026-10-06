/*
 * Pruebas de carga con k6.
 *
 * Proposito
 *   Medir latencia y comportamiento bajo concurrencia de las operaciones
 *   que un dia de trabajo real ejercita: listar registros, consultar la
 *   cola de revision y lanzar escaneos.
 *
 * Un solo fichero con escenarios y no un script por caso: comparten la
 * configuracion, las cabeceras y los umbrales, y repartirlos obligaria a
 * repetir todo eso en cada uno.
 *
 *   k6 run --env ESCENARIO=humo     pruebas-de-carga/carga.js
 *   k6 run --env ESCENARIO=lectura  --env TOKEN=... pruebas-de-carga/carga.js
 *   k6 run --env ESCENARIO=escaneos --env TOKEN=... --env CONEXION_ID=... pruebas-de-carga/carga.js
 *
 * Sobre el token
 *   La API verifica la firma contra el JWKS del proveedor de identidad, y
 *   no tiene ninguna pasarela para entornos de desarrollo: es
 *   deliberado, porque una pasarela asi es exactamente la que alguien
 *   deja abierta en produccion. Los escenarios autenticados reciben por
 *   tanto un access token real en `TOKEN`, y su sitio natural es
 *   staging, que es donde las cifras significan algo. Medir en un
 *   portatil con todo en Docker da numeros que no sirven para
 *   dimensionar nada.
 *
 *   `humo` no necesita token y si corre en cualquier sitio: comprueba que
 *   el servicio responde y que los endpoints protegidos siguen
 *   rechazando a quien no se identifica.
 */

import http from "k6/http";
import { check, group, sleep } from "k6";
import { Counter, Trend } from "k6/metrics";

// Por defecto k6 considera fallida cualquier respuesta fuera de 2xx/3xx,
// asi que un 401 o un 429 —que aqui son la respuesta correcta— dispararian
// el umbral de errores y lo volverian inutil. Lo que debe fallar la prueba
// es un 5xx o un error de red.
http.setResponseCallback(http.expectedStatuses({ min: 200, max: 499 }));

const BASE = __ENV.BASE_URL || "http://localhost:8000";
const TOKEN = __ENV.TOKEN || "";
const CONEXION_ID = __ENV.CONEXION_ID || "";
const ESCENARIO = __ENV.ESCENARIO || "humo";

// Metricas propias: `http_req_duration` mezcla todas las peticiones de un
// escenario, y lo que interesa comparar es cada operacion por separado.
const duracionDeListado = new Trend("duracion_listado_registros", true);
const duracionDeCola = new Trend("duracion_cola_de_revision", true);
const escaneosAceptados = new Counter("escaneos_aceptados");
const escaneosLimitados = new Counter("escaneos_limitados_por_cuota");

const TODOS_LOS_ESCENARIOS = {
  // Comprobacion de vida, sin token. Un solo VU y una iteracion a
  // proposito: las comprobaciones tienen que ocurrir en orden, porque la
  // ultima agota deliberadamente el limitador de peticiones y a partir de
  // ahi todo responde 429. Con varios VUs en paralelo unas pisarian a
  // otras y el resultado dependeria del azar.
  humo: {
    executor: "per-vu-iterations",
    vus: 1,
    iterations: 1,
    maxDuration: "2m",
    exec: "humo",
    tags: { escenario: "humo" },
  },

  // Lectura sostenida: es el perfil dominante: el operador consulta
  // mucho mas de lo que escribe.
  lectura: {
    executor: "ramping-vus",
    startVUs: 1,
    stages: [
      { duration: "30s", target: 20 },
      { duration: "2m", target: 20 },
      { duration: "30s", target: 0 },
    ],
    exec: "lectura",
    tags: { escenario: "lectura" },
  },

  // 50 escaneos concurrentes, que es el objetivo declarado en el plan de
  // arquitectura. Lo que se mide aqui no es la latencia del escaneo
  // —ocurre en un worker— sino que la API encole sin degradarse y que la
  // cuota por tenant corte en lugar de dejar crecer la cola sin limite.
  escaneos: {
    executor: "per-vu-iterations",
    vus: 50,
    iterations: 1,
    maxDuration: "2m",
    exec: "escaneos",
    tags: { escenario: "escaneos" },
  },
};

export const options = {
  scenarios: { [ESCENARIO]: TODOS_LOS_ESCENARIOS[ESCENARIO] },
  thresholds: {
    // Un error de red o un 5xx bajo esta carga es un fallo, no ruido.
    http_req_failed: ["rate<0.01"],
    // El objetivo del plan de arquitectura para lecturas.
    "duracion_listado_registros{escenario:lectura}": ["p(95)<300"],
    "duracion_cola_de_revision{escenario:lectura}": ["p(95)<300"],
    // Encolar es una escritura barata: no debe acercarse al segundo.
    "http_req_duration{escenario:escaneos}": ["p(95)<1000"],
  },
};

function cabeceras() {
  const base = { Accept: "application/json" };
  return TOKEN ? Object.assign(base, { Authorization: `Bearer ${TOKEN}` }) : base;
}

export function setup() {
  // Falla antes de empezar si el servicio no esta en pie: una suite que
  // mide 200 ms de 404 no dice nada y se tarda en descubrir.
  const vivo = http.get(`${BASE}/health/live`);
  if (vivo.status !== 200) {
    throw new Error(`El servicio no responde en ${BASE}: ${vivo.status}`);
  }

  if (ESCENARIO !== "humo" && !TOKEN) {
    throw new Error(
      `El escenario '${ESCENARIO}' necesita un access token valido en la variable TOKEN.`,
    );
  }
  if (ESCENARIO === "escaneos" && !CONEXION_ID) {
    throw new Error("El escenario 'escaneos' necesita CONEXION_ID: el buzon contra el que escanear.");
  }
  return {};
}

export function humo() {
  group("sondas de salud", () => {
    const vivo = http.get(`${BASE}/health/live`);
    check(vivo, { "live responde 200": (r) => r.status === 200 });

    const listo = http.get(`${BASE}/health/ready`);
    check(listo, {
      "ready responde 200 o 503": (r) => r.status === 200 || r.status === 503,
      "ready informa de cada componente": (r) => {
        const cuerpo = r.json();
        return Boolean(cuerpo && cuerpo.data && cuerpo.data.componentes);
      },
    });
  });

  group("los endpoints protegidos siguen protegidos", () => {
    // Es la trampa clasica de una prueba de carga: medir latencias
    // excelentes sobre un monton de 401 y concluir que el sistema va
    // rapido. Si esto deja de dar 401, el resto de las cifras no valen.
    for (const ruta of ["/api/v1/records", "/api/v1/scans", "/api/v1/me", "/api/v1/audit"]) {
      const respuesta = http.get(`${BASE}${ruta}`, { headers: { Accept: "application/json" } });
      check(respuesta, {
        [`${ruta} exige autenticacion`]: (r) => r.status === 401,
        [`${ruta} no filtra detalles del servidor`]: (r) =>
          !String(r.body).includes("Traceback") && !String(r.body).includes("sqlalchemy"),
      });
      // Separadas en el tiempo para no agotar el limitador antes de la
      // comprobacion siguiente: el limite por defecto son 120 por minuto.
      sleep(0.3);
    }
  });

  group("el limitador corta una rafaga", () => {
    // Esto no lo verifica ningun otro test: que el limitador actue de
    // verdad bajo concurrencia y ANTES de autenticar, que es el orden
    // correcto —no tiene sentido gastar CPU verificando firmas de un
    // flujo que se va a rechazar.
    let limitadas = 0;
    let respuestaLimitada = null;
    for (let i = 0; i < 200; i += 1) {
      const respuesta = http.get(`${BASE}/api/v1/records`, {
        headers: { Accept: "application/json" },
      });
      if (respuesta.status === 429) {
        limitadas += 1;
        respuestaLimitada = respuesta;
      }
    }

    check(
      { limitadas, respuestaLimitada },
      {
        "una rafaga acaba limitada": (datos) => datos.limitadas > 0,
        "el 429 llega como Problem Details": (datos) => {
          if (!datos.respuestaLimitada) return false;
          const cuerpo = datos.respuestaLimitada.json();
          return Boolean(cuerpo && cuerpo.type && String(cuerpo.type).startsWith("urn:mailauto:"));
        },
      },
    );
  });
}

export function lectura() {
  group("listado de registros", () => {
    const respuesta = http.get(`${BASE}/api/v1/records?limite=25`, { headers: cabeceras() });
    duracionDeListado.add(respuesta.timings.duration);
    check(respuesta, { "listado responde 200": (r) => r.status === 200 });

    // Segunda pagina por cursor: es la consulta que mas se degrada si
    // falta un indice, y la que un listado con OFFSET haria lenta.
    const cuerpo = respuesta.status === 200 ? respuesta.json() : null;
    const cursor = cuerpo && cuerpo.meta ? cuerpo.meta.cursor : null;
    if (cursor) {
      const siguiente = http.get(
        `${BASE}/api/v1/records?limite=25&cursor=${encodeURIComponent(cursor)}`,
        { headers: cabeceras() },
      );
      duracionDeListado.add(siguiente.timings.duration);
      check(siguiente, { "pagina siguiente responde 200": (r) => r.status === 200 });
    }
  });

  group("cola de revision", () => {
    const cola = http.get(`${BASE}/api/v1/review?limite=25`, { headers: cabeceras() });
    duracionDeCola.add(cola.timings.duration);
    check(cola, { "cola responde 200": (r) => r.status === 200 });

    const conteo = http.get(`${BASE}/api/v1/review/count`, { headers: cabeceras() });
    check(conteo, { "conteo responde 200": (r) => r.status === 200 });
  });

  // Pausa entre iteraciones: un operador real no pulsa sin parar, y sin
  // ella la prueba mide el techo del bucle en lugar de un uso plausible.
  sleep(Math.random() * 2 + 1);
}

export function escaneos() {
  const respuesta = http.post(
    `${BASE}/api/v1/scans`,
    JSON.stringify({ conexion_id: CONEXION_ID, limite_de_mensajes: 50 }),
    { headers: Object.assign(cabeceras(), { "Content-Type": "application/json" }) },
  );

  if (respuesta.status === 201 || respuesta.status === 200) {
    escaneosAceptados.add(1);
  } else if (respuesta.status === 429) {
    // No es un fallo: es la cuota por tenant haciendo su trabajo. Lo
    // contrario —aceptar los 50— seria el problema.
    escaneosLimitados.add(1);
  }

  check(respuesta, {
    "la API responde sin error de servidor": (r) => r.status < 500,
    "acepta o limita, no rompe": (r) =>
      r.status === 201 || r.status === 200 || r.status === 429 || r.status === 409,
  });
}
