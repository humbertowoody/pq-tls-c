#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "kyber/ref/api.h"
#include "dilithium/ref/api.h"
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// Constantes de configuración de red.
#define PUERTO_SERVIDOR 8080
#define HOST_SERVIDOR "127.0.0.1"

// Función para enviar datos a un socket.
void enviar(int sockfd, const unsigned char *datos, size_t longitud_datos)
{
  // Enviamos la longitud de los datos como un entero de 64 bits
  uint64_t len_net = htonll(longitud_datos); // Convierte de host a orden de red
  send(sockfd, &len_net, sizeof(len_net), 0);

  // Enviamos los datos en bloques
  size_t enviado = 0;
  while (enviado < longitud_datos)
  {
    size_t tam_bloque = (longitud_datos - enviado > 4096) ? 4096 : longitud_datos - enviado;
    send(sockfd, datos + enviado, tam_bloque, 0);
    enviado += tam_bloque;
  }
}

// Función para recibir datos de un socket.
unsigned char *recibir(int sockfd, size_t *longitud_datos)
{
  // Recibimos la longitud de los datos
  uint64_t len_net;
  recv(sockfd, &len_net, sizeof(len_net), 0);
  *longitud_datos = ntohll(len_net); // Convierte de orden de red a host

  // Asignamos memoria para los datos a recibir
  unsigned char *datos = (unsigned char *)malloc(*longitud_datos);

  // Recibimos los datos en bloques
  size_t recibido = 0;
  while (recibido < *longitud_datos)
  {
    size_t tam_bloque = (*longitud_datos - recibido > 4096) ? 4096 : *longitud_datos - recibido;
    ssize_t n = recv(sockfd, datos + recibido, tam_bloque, 0);
    if (n <= 0)
    {
      free(datos); // Liberamos los recursos en caso de error
      return NULL;
    }
    recibido += n;
  }

  return datos;
}

// Función para shakear una clave.
void shake_key(const unsigned char *clave, size_t clave_len, unsigned char *salida, int length)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha256();
  EVP_DigestInit_ex(ctx, md, NULL);
  EVP_DigestUpdate(ctx, clave, clave_len);
  EVP_DigestFinal_ex(ctx, salida, NULL);
  EVP_MD_CTX_free(ctx);
}

// Función para cifrar con AES.
int cifrar_aes(const unsigned char *mensaje, size_t mensaje_len, const unsigned char *clave, unsigned char **mensaje_cifrado)
{
  int outlen, tmplen, iv_len = AES_BLOCK_SIZE;
  unsigned char iv[AES_BLOCK_SIZE]; // Inicialización del vector
  if (!RAND_bytes(iv, sizeof(iv)))
    return 0; // Genera IV aleatorio

  *mensaje_cifrado = (unsigned char *)malloc(iv_len + mensaje_len + AES_BLOCK_SIZE); // Espacio para IV + padding
  if (*mensaje_cifrado == NULL)
    return 0;

  memcpy(*mensaje_cifrado, iv, iv_len); // Prepende el IV al mensaje cifrado

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clave, iv);
  EVP_EncryptUpdate(ctx, *mensaje_cifrado + iv_len, &outlen, mensaje, mensaje_len);
  EVP_EncryptFinal_ex(ctx, *mensaje_cifrado + iv_len + outlen, &tmplen);
  EVP_CIPHER_CTX_free(ctx);

  return iv_len + outlen + tmplen; // Retorna el tamaño del mensaje cifrado
}

// Función para descifrar con AES.
int descifrar_aes(const unsigned char *mensaje_cifrado, size_t mensaje_cifrado_len, const unsigned char *clave, unsigned char **mensaje)
{
  int outlen, tmplen, iv_len = AES_BLOCK_SIZE;
  const unsigned char *iv = mensaje_cifrado; // IV está al principio del mensaje cifrado

  *mensaje = (unsigned char *)malloc(mensaje_cifrado_len + AES_BLOCK_SIZE); // Espacio para el mensaje descifrado
  if (*mensaje == NULL)
    return 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clave, iv);
  EVP_DecryptUpdate(ctx, *mensaje, &outlen, mensaje_cifrado + iv_len, mensaje_cifrado_len - iv_len);
  if (!EVP_DecryptFinal_ex(ctx, *mensaje + outlen, &tmplen))
  {
    EVP_CIPHER_CTX_free(ctx);
    free(*mensaje);
    return 0; // Error en descifrado, podría ser debido a padding incorrecto
  }
  EVP_CIPHER_CTX_free(ctx);

  return outlen + tmplen; // Retorna el tamaño del mensaje descifrado
}

// Estructura para los argumentos de los hilos clientes, que incluye el ID del cliente y el nivel de verificación.
typedef struct
{
  int id_cliente;
  int nivel_verificacion;
} argumentos_cliente;

// Función para el hilo del cliente.
void *cliente(void *arg)
{
  // Extraer los argumentos.
  int id_cliente = ((argumentos_cliente *)arg)->id_cliente;
  int nivel_verificacion = ((argumentos_cliente *)arg)->nivel_verificacion;

  // Mensaje de inicio.
  printf("[Cliente %d]: Iniciando cliente...\n", id_cliente);

  // Crear el socket del cliente.
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
  {
    printf("[Cliente %d]: Error creando el socket\n", id_cliente);
    return NULL;
  }
  printf("[Cliente %d]: Socket creado\n", id_cliente);

  // Configurar el socket del cliente.
  struct sockaddr_in direccion_servidor;
  direccion_servidor.sin_family = AF_INET;
  direccion_servidor.sin_port = htons(PUERTO_SERVIDOR);
  direccion_servidor.sin_addr.s_addr = inet_addr(HOST_SERVIDOR);
  memset(direccion_servidor.sin_zero, 0, sizeof(direccion_servidor.sin_zero));

  // Conectar el socket del cliente.
  if (connect(sockfd, (struct sockaddr *)&direccion_servidor, sizeof(struct sockaddr_in)) == -1)
  {
    printf("[Cliente %d]: Error conectando el socket\n", id_cliente);
    return NULL;
  }
  printf("[Cliente %d]: Conexión establecida\n", id_cliente);

  // Inicio del KEM.
  printf("[Cliente %d]: Iniciando KEM...\n", id_cliente);

  // Generar las claves de Kyber.
  unsigned char kyber_pk[pqcrystals_kyber512_PUBLICKEYBYTES];
  unsigned char kyber_sk[pqcrystals_kyber512_SECRETKEYBYTES];
  if (pqcrystals_kyber512_ref_keypair(kyber_pk, kyber_sk) != 0)
  {
    printf("[Cliente %d]: Error generando las llaves de Kyber\n", id_cliente);
    return NULL;
  }
  printf("[Cliente %d]: Llaves de Kyber generadas\n", id_cliente);

  // Enviar la llave pública de Kyber al servidor.
  enviar(sockfd, kyber_pk, pqcrystals_kyber512_PUBLICKEYBYTES);
  printf("[Cliente %d]: Llave pública de Kyber enviada al servidor\n", id_cliente);

  // Recibir el ciphertext de Kyber del servidor.
  size_t longitud_datos;
  unsigned char *kyber_ciphertext = recibir(sockfd, &longitud_datos);
  if (kyber_ciphertext == NULL)
  {
    printf("[Cliente %d]: Error recibiendo el ciphertext de Kyber del servidor\n", id_cliente);
    return NULL;
  }
  printf("[Cliente %d]: Ciphertext de Kyber recibido del servidor con longitud %lu\n", id_cliente, longitud_datos);

  // Desencapsular la llave secreta de Kyber y generar shared secret.
  unsigned char kyber_shared_secret[pqcrystals_kyber512_BYTES];
  if (pqcrystals_kyber512_ref_dec(kyber_shared_secret, kyber_ciphertext, kyber_sk) != 0)
  {
    printf("[Cliente %d]: Error desencapsulando la llave secreta de Kyber del servidor\n", id_cliente);
    return NULL;
  }
  printf("[Cliente %d]: Llave secreta de Kyber desencapsulada del servidor con longitud %lu\n", id_cliente, pqcrystals_kyber512_BYTES);

  // Shakear el shared secret de Kyber para obtener la clave AES.

  // Según el argumento de nivel de verificación Dilithium, se envía la llave pública de Kyber y se verifica la llave secreta de Kyber.
  if (nivel_verificacion == 2 || nivel_verificacion == 3)
  {
    // Generar las claves de Dilithium.
    unsigned char dilithium_pk[pqcrystals_dilithium2_PUBLICKEYBYTES];
    unsigned char dilithium_sk[pqcrystals_dilithium2_SECRETKEYBYTES];
    if (pqcrystals_dilithium2_ref_keypair(dilithium_pk, dilithium_sk) != 0)
    {
      printf("[Cliente %d]: Error generando las llaves de Dilithium\n", id_cliente);
      return NULL;
    }
    printf("[Cliente %d]: Llaves de Dilithium generadas\n", id_cliente);

    // Firmar el texto "Certificado del cliente" con la llave privada de Dilithium.
    unsigned char dilithium_cert[pqcrystals_dilithium2_BYTES];
    size_t longitud_cert;
    if (pqcrystals_dilithium2_ref_signature(dilithium_cert, &longitud_cert, "Certificado del cliente", 20, dilithium_sk) != 0)
    {
      printf("[Cliente %d]: Error firmando el texto con la llave privada de Dilithium\n", id_cliente);
      return NULL;
    }
    printf("[Cliente %d]: Texto firmado con la llave privada de Dilithium\n", id_cliente);

    // Enviar el certificado de Dilithium al servidor.
    enviar(sockfd, dilithium_cert, pqcrystals_dilithium2_BYTES);
    printf("[Cliente %d]: Certificado de Dilithium enviado al servidor\n", id_cliente);

    // Enviar la llave pública de Dilithium al servidor.
    enviar(sockfd, dilithium_pk, pqcrystals_dilithium2_PUBLICKEYBYTES);
    printf("[Cliente %d]: Llave pública de Dilithium enviada al servidor\n", id_cliente);
  }
  else if (nivel_verificacion == 3)
  {
    // Recibir el certificado de Dilithium del servidor.
    unsigned char *dilithium_cert_servidor = recibir(sockfd, &longitud_datos);
    if (dilithium_cert_servidor == NULL)
    {
      printf("[Cliente %d]: Error recibiendo el certificado de Dilithium del servidor\n", id_cliente);
      return NULL;
    }
    printf("[Cliente %d]: Certificado de Dilithium del servidor recibido con longitud %lu\n", id_cliente, longitud_datos);

    // Recibir la llave pública de Dilithium del servidor.
    unsigned char *dilithium_pk_servidor = recibir(sockfd, &longitud_datos);
    if (dilithium_pk_servidor == NULL)
    {
      printf("[Cliente %d]: Error recibiendo la llave pública de Dilithium del servidor\n", id_cliente);
      return NULL;
    }
    printf("[Cliente %d]: Llave pública de Dilithium del servidor recibida con longitud %lu\n", id_cliente, longitud_datos);

    // Verificamos que el certificado de Dilithium del servidor sea válido con su llave pública para el texto "Certificado del servidor"
    if (pqcrystals_dilithium2_ref_verify(dilithium_cert_servidor, longitud_datos, "Certificado del servidor", 23, dilithium_pk_servidor) != 0)
    {
      printf("[Cliente %d]: Error verificando el certificado de Dilithium del servidor\n", id_cliente);
      return NULL;
    }
    printf("[Cliente %d]: Certificado de Dilithium del servidor verificado\n", id_cliente);
  }
  else
  {
    printf("[Cliente %d]: No se verificarán los certificados de Dilithium\n", id_cliente);
  }

  // Cerrar el socket del cliente.
  close(sockfd);

  // Mensaje de fin.
  printf("[Cliente %d]: Fin del cliente\n", id_cliente);

  return NULL;
}

// Función principal.
int main(int argc, char *argv[])
{
  // Variables locales.
  int nivel_verificacion,                                           // Nivel de verificación
      n_bytes;                                                      // Cantidad de bytes para las pruebas.
  unsigned char dilithium_pk[pqcrystals_dilithium2_PUBLICKEYBYTES], // Llave pública de Dilithium (Servidor).
      dilithium_sk[pqcrystals_dilithium2_SECRETKEYBYTES];           // Llave privada de Dilithium (Servidor).

  // Análisis de argumentos.
  if (argc != 3)
  {
    printf("Uso: %s <nivel_verificacion> <n_bytes>\n", argv[0]);
    printf("\t- nivel_verificacion: Nivel de verificación (1 - sin verificación, 2 - clientes o 3 - clientes + servidor).\n");
    printf("\t- n_bytes: Cantidad de bytes a transmitir.\n");
    return 1;
  }

  // Obtener el nivel de verificación.
  nivel_verificacion = atoi(argv[1]);

  // Validar el nivel de verificación.
  if (nivel_verificacion < 1 || nivel_verificacion > 3)
  {
    printf("El nivel de verificación debe ser 1, 2 o 3.\n");
    return 1;
  }

  // Obtener la cantidad de bytes.
  n_bytes = atoi(argv[2]);

  // Validar la cantidad de bytes.
  if (n_bytes < 1)
  {
    printf("La cantidad de bytes debe ser mayor a 0.\n");
    return 1;
  }

  // Imprimimos los argumentos del programa.
  printf("Argumentos del programa:\n");
  switch (nivel_verificacion)
  {
  case 1:
    printf("\t- Nivel de verificación: No se verificarán los clientes ni el servidor.\n");
    break;
  case 2:
    printf("\t- Nivel de verificación: Se verificarán los clientes pero no el servidor.\n");
    break;
  case 3:
    printf("\t- Nivel de verificación: Se verificarán los clientes y el servidor.\n");
    break;
  }
  printf("\t- Cantidad de bytes a transmitir: %d\n", n_bytes);

  // Generar las claves de Dilithium para el servidor.
  if (pqcrystals_dilithium2_ref_keypair(dilithium_pk, dilithium_sk) != 0)
  {
    printf("[Servidor]: Error generando las llaves de Dilithium\n");
    return 1;
  }

  // Mensaje de inicio.
  printf("[Servidor]: Iniciando servidor...\n");

  // Crear el socket del servidor.
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
  {
    printf("[Servidor]: Error creando el socket\n");
    return 1;
  }
  printf("[Servidor]: Socket creado\n");

  // Configurar el socket del servidor.
  struct sockaddr_in direccion_servidor;
  direccion_servidor.sin_family = AF_INET;
  direccion_servidor.sin_port = htons(PUERTO_SERVIDOR);
  direccion_servidor.sin_addr.s_addr = inet_addr(HOST_SERVIDOR);
  memset(direccion_servidor.sin_zero, 0, sizeof(direccion_servidor.sin_zero));

  // Colocar la opción REUSEADDR en el socket del servidor.
  int yes = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
  {
    printf("[Servidor]: Error colocando la opción REUSEADDR en el socket\n");
    return 1;
  }
  printf("[Servidor]: Opción REUSEADDR colocada en el socket\n");

  // Enlazar el socket del servidor.
  if (bind(sockfd, (struct sockaddr *)&direccion_servidor, sizeof(direccion_servidor)) == -1)
  {
    printf("[Servidor]: Error enlazando el socket\n");
    return 1;
  }
  printf("[Servidor]: Socket enlazado\n");

  // Escuchar en el socket del servidor.
  if (listen(sockfd, 5) == -1)
  {
    printf("[Servidor]: Error escuchando en el socket\n");
    return 1;
  }
  printf("[Servidor]: Escuchando en el socket\n");

  // Lanzamos los hilos de los dos clientes con los argumentos correspondientes.
  pthread_t hilo_cliente_1, hilo_cliente_2;
  argumentos_cliente arg_cliente_1 = {1, nivel_verificacion};
  argumentos_cliente arg_cliente_2 = {2, nivel_verificacion};
  pthread_create(&hilo_cliente_1, NULL, cliente, &arg_cliente_1);
  pthread_create(&hilo_cliente_2, NULL, cliente, &arg_cliente_2);
  printf("[Servidor]: Hilos de los clientes lanzados\n");

  // Aceptar la conexión de un cliente.
  struct sockaddr_in direccion_cliente_1;
  socklen_t tamano_direccion_cliente_1 = sizeof(struct sockaddr_in);
  int cliente_1 = accept(sockfd, (struct sockaddr *)&direccion_cliente_1, &tamano_direccion_cliente_1);
  if (cliente_1 == -1)
  {
    printf("[Servidor]: Error aceptando la conexión del cliente 1\n");
    return 1;
  }
  printf("[Servidor]: Conexión aceptada del cliente 1\n");

  // Aceptar la conexión de un cliente.
  struct sockaddr_in direccion_cliente_2;
  socklen_t tamano_direccion_cliente_2 = sizeof(struct sockaddr_in);
  int cliente_2 = accept(sockfd, (struct sockaddr *)&direccion_cliente_2, &tamano_direccion_cliente_2);
  if (cliente_2 == -1)
  {
    printf("[Servidor]: Error aceptando la conexión del cliente 2\n");
    return 1;
  }
  printf("[Servidor]: Conexión aceptada del cliente 2\n");

  // Inicio del KEM.
  printf("[Servidor]: Iniciando KEM...\n");

  // Recibir la llave pública de Kyber del cliente 1.
  size_t longitud_datos;
  unsigned char *kyber_pk_cliente_1 = recibir(cliente_1, &longitud_datos);
  if (kyber_pk_cliente_1 == NULL)
  {
    printf("[Servidor]: Error recibiendo la llave pública de Kyber del cliente 1\n");
    return 1;
  }
  printf("[Servidor]: Llave pública de Kyber del cliente 1 recibida con longitud %lu\n", longitud_datos);

  // Recibir la llave pública de Kyber del cliente 2.
  unsigned char *kyber_pk_cliente_2 = recibir(cliente_2, &longitud_datos);
  if (kyber_pk_cliente_2 == NULL)
  {
    printf("[Servidor]: Error recibiendo la llave pública de Kyber del cliente 2\n");
    return 1;
  }
  printf("[Servidor]: Llave pública de Kyber del cliente 2 recibida con longitud %lu\n", longitud_datos);

  // Encapsular la llave secreta de Kyber para el cliente 1 y generar ciphertext y shared secret.
  unsigned char kyber_ciphertext_cliente_1[pqcrystals_kyber512_CIPHERTEXTBYTES];
  unsigned char kyber_shared_secret_cliente_1[pqcrystals_kyber512_BYTES];
  if (pqcrystals_kyber512_ref_enc(kyber_ciphertext_cliente_1, kyber_shared_secret_cliente_1, kyber_pk_cliente_1) != 0)
  {
    printf("[Servidor]: Error encapsulando la llave secreta de Kyber para el cliente 1\n");
    return 1;
  }
  printf("[Servidor]: Llave secreta de Kyber encapsulada para el cliente 1\n");

  // Encapsular la llave secreta de Kyber para el cliente 2 y generar ciphertext y shared secret.
  unsigned char kyber_ciphertext_cliente_2[pqcrystals_kyber512_CIPHERTEXTBYTES];
  unsigned char kyber_shared_secret_cliente_2[pqcrystals_kyber512_BYTES];
  if (pqcrystals_kyber512_ref_enc(kyber_ciphertext_cliente_2, kyber_shared_secret_cliente_2, kyber_pk_cliente_2) != 0)
  {
    printf("[Servidor]: Error encapsulando la llave secreta de Kyber para el cliente 2\n");
    return 1;
  }
  printf("[Servidor]: Llave secreta de Kyber encapsulada para el cliente 2\n");

  // Enviar el ciphertext de Kyber al cliente 1.
  enviar(cliente_1, kyber_ciphertext_cliente_1, pqcrystals_kyber512_CIPHERTEXTBYTES);
  printf("[Servidor]: Ciphertext de Kyber enviado al cliente 1 con longitud %lu\n", pqcrystals_kyber512_CIPHERTEXTBYTES);

  // Enviar el ciphertext de Kyber al cliente 2.
  enviar(cliente_2, kyber_ciphertext_cliente_2, pqcrystals_kyber512_CIPHERTEXTBYTES);
  printf("[Servidor]: Ciphertext de Kyber enviado al cliente 2 con longitud %lu\n", pqcrystals_kyber512_CIPHERTEXTBYTES);

  // Shakear la llave secreta de Kyber para el cliente 1.
  shake_key(kyber_shared_secret_cliente_1, pqcrystals_kyber512_BYTES, kyber_shared_secret_cliente_1, pqcrystals_kyber512_BYTES);
  printf("[Servidor]: Llave secreta de Kyber shakeada para el cliente 1\n");

  // Shakear la llave secreta de Kyber para el cliente 2.
  shake_key(kyber_shared_secret_cliente_2, pqcrystals_kyber512_BYTES, kyber_shared_secret_cliente_2, pqcrystals_kyber512_BYTES);
  printf("[Servidor]: Llave secreta de Kyber shakeada para el cliente 2\n");

  // Según el argumento de nivel de verificación Dilithium, se verifica la llave secreta de Kyber.
  if (nivel_verificacion == 2 || nivel_verificacion == 3)
  {
    // Recibir el certificado de Dilithium del cliente 1.
    unsigned char *dilithium_cert_cliente_1 = recibir(cliente_1, &longitud_datos);
    if (dilithium_cert_cliente_1 == NULL)
    {
      printf("[Servidor]: Error recibiendo el certificado de Dilithium del cliente 1\n");
      return 1;
    }
    printf("[Servidor]: Certificado de Dilithium del cliente 1 recibido con longitud %lu\n", longitud_datos);

    // Recibir la llave pública de Dilithium del cliente 1.
    unsigned char *dilithium_pk_cliente_1 = recibir(cliente_1, &longitud_datos);
    if (dilithium_pk_cliente_1 == NULL)
    {
      printf("[Servidor]: Error recibiendo la llave pública de Dilithium del cliente 1\n");
      return 1;
    }
    printf("[Servidor]: Llave pública de Dilithium del cliente 1 recibida con longitud %lu\n", longitud_datos);

    // Verificamos que el certificado de Dilithium del cliente 1 sea válido con su llave pública para el texto "Certificado del cliente"
    if (pqcrystals_dilithium2_ref_verify(dilithium_cert_cliente_1, longitud_datos, "Certificado del cliente", 20, dilithium_pk_cliente_1) != 0)
    {
      printf("[Servidor]: Error verificando el certificado de Dilithium del cliente 1\n");
      return 1;
    }
    printf("[Servidor]: Certificado de Dilithium del cliente 1 verificado\n");

    // Recibir el certificado de Dilithium del cliente 2.
    unsigned char *dilithium_cert_cliente_2 = recibir(cliente_2, &longitud_datos);
    if (dilithium_cert_cliente_2 == NULL)
    {
      printf("[Servidor]: Error recibiendo el certificado de Dilithium del cliente 2\n");
      return 1;
    }
    printf("[Servidor]: Certificado de Dilithium del cliente 2 recibido con longitud %lu\n", longitud_datos);

    // Recibir la llave pública de Dilithium del cliente 2.
    unsigned char *dilithium_pk_cliente_2 = recibir(cliente_2, &longitud_datos);
    if (dilithium_pk_cliente_2 == NULL)
    {
      printf("[Servidor]: Error recibiendo la llave pública de Dilithium del cliente 2\n");
      return 1;
    }
    printf("[Servidor]: Llave pública de Dilithium del cliente 2 recibida con longitud %lu\n", longitud_datos);

    // Verificamos que el certificado de Dilithium del cliente 2 sea válido con su llave pública para el texto "Certificado del cliente"
    if (pqcrystals_dilithium2_ref_verify(dilithium_cert_cliente_2, longitud_datos, "Certificado del cliente", 20, dilithium_pk_cliente_2) != 0)
    {
      printf("[Servidor]: Error verificando el certificado de Dilithium del cliente 2\n");
      return 1;
    }
    printf("[Servidor]: Certificado de Dilithium del cliente 2 verificado\n");
  }
  else if (nivel_verificacion == 3)
  {
    printf("[Servidor]: Enviando certificado y llave pública de Dilithium a los clientes\n");

    // Firmar el texto "Certificado del servidor" con la llave privada de Dilithium.
    unsigned char dilithium_cert_servidor[pqcrystals_dilithium2_BYTES];
    size_t longitud_cert_servidor;
    if (pqcrystals_dilithium2_ref_signature(dilithium_cert_servidor, &longitud_cert_servidor, "Certificado del servidor", 23, dilithium_sk) != 0)
    {
      printf("[Servidor]: Error firmando el texto con la llave privada de Dilithium\n");
      return 1;
    }
    printf("[Servidor]: Texto firmado con la llave privada de Dilithium\n");

    // Enviar el certificado de Dilithium a los clientes.
    enviar(cliente_1, dilithium_cert_servidor, pqcrystals_dilithium2_BYTES);
    enviar(cliente_2, dilithium_cert_servidor, pqcrystals_dilithium2_BYTES);
    printf("[Servidor]: Certificado de Dilithium enviado a los clientes con longitud %lu\n", pqcrystals_dilithium2_BYTES);
  }
  else
  {
    printf("[Servidor]: No se verificarán los certificados de Dilithium\n");
  }

  // For Kyber512
  // unsigned char kyber_pk[pqcrystals_kyber512_PUBLICKEYBYTES];
  // unsigned char kyber_sk[pqcrystals_kyber512_SECRETKEYBYTES];

  // For Dilithium2
  // unsigned char dilithium_pk[pqcrystals_dilithium2_PUBLICKEYBYTES];
  // unsigned char dilithium_sk[pqcrystals_dilithium2_SECRETKEYBYTES];

  //// Generate Kyber key pair
  // if (pqcrystals_kyber512_ref_keypair(kyber_pk, kyber_sk) != 0) {
  //     printf("Kyber key generation failed\n");
  //     return 1;
  // }

  //// Generate Dilithium key pair

  // printf("Kyber and Dilithium key generation successful\n");

  // Esperamos a que los hilos terminen.
  pthread_join(hilo_cliente_1, NULL);
  pthread_join(hilo_cliente_2, NULL);

  // Cerrar el socket del servidor.
  close(sockfd);

  // Mensaje de fin.
  printf("Fin del programa\n");

  return 0;
}
