package tcp_cifrado;

import DiffieHellman.DiffieHellman;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * Cliente TCP que envía una frase cifrada con el algoritmo simétrico
 * DES y que realiza un intercambio de claves Diffie-Hellman con el 
 * servidor TCP.
 * 
 * @version 1.7 18/04/2022
 * @author Raquel Romero Pedraza
 * 
 */

public class ClienteTCP {

    /**
     * Método principal de la clase:
     *
     * @param argumentos
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.NoSuchProviderException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws java.lang.ClassNotFoundException
     */
    public static void main(String[] argumentos) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, ClassNotFoundException {
        int puerto = 8888;
        String direccionServidor = "127.0.0.1";

        // Argumentos por la línea de comandos:
        if (argumentos.length == 2) {
            direccionServidor = argumentos[0];
            puerto = Integer.parseInt(argumentos[1]);
        }

        // Cliente:
        new ClienteTCP(direccionServidor, puerto);

    }

    /**
     * Constructor del cliente.
     *
     * @param direccionServidor Dirección o nombre del servidor.
     * @param puerto Puerto donde escucha el servidor.
     */
    private ClienteTCP(String direccionServidor, int puerto) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, ClassNotFoundException {
        Socket socketConexion;
        byte[] mensajeCifrado;

        try {
            // Abrimos la conexión.
            socketConexion = new Socket(direccionServidor, puerto);

            // Para leer de la línea de comandos:
            BufferedReader inConsola = new BufferedReader(new InputStreamReader(System.in));
            
            // Obtenemos el canal de entrada/salida:
            BufferedReader in = new BufferedReader(new InputStreamReader(socketConexion.getInputStream()));
            PrintWriter out = new PrintWriter(socketConexion.getOutputStream());
            
            mostrar("Conexión con servidor establecida\n", false);

            ////////////////////////////////////////////////////////////////
            // INTERCAMBIO DE CLAVES DIFFIE-HELLMAN ///////////////////////
            //////////////////////////////////////////////////////////////
            
            mostrar("Realizando intercambio de claves Diffie-Hellman\n", false);
            
            // Objeto DiffieHellman para hacer el intercambio
            final DiffieHellman client = new DiffieHellman();
            
            // Creamos un canal para intercambio de objetos ya que se van a
            // intercambiar claves (objeto PublicKey)
            PublicKey publicKey_Server;
            
            client.generateKeys();
                        
            // Canal de entrada de objetos 
            ObjectInputStream keyIn = new ObjectInputStream(socketConexion.getInputStream());
            
            // Recibela clave pública del server
            publicKey_Server = (PublicKey) keyIn.readObject();
            client.receivePublicKeyFrom(publicKey_Server);
            
            // Canal de salida de objetos
            ObjectOutputStream outO = new ObjectOutputStream(socketConexion.getOutputStream());
            
            // Manda la clave pública del cliente
            outO.writeObject(client.getPublicKey());
            outO.flush();

            // Genera la clave secreta compartida
            client.generateCommonSecretKey();
            mostrar("Intercambio Diffie-Hellaman terminado\n", false);

            ////////////////////////////////////////////////////////////////////
            
            mostrar("Escriba una frase para sustituir sus vocales o escriba 'adios' para salir\n", false);
            mostrar("Inserte la frase: \n", false);
            
            String mensaje = inConsola.readLine();

            // Cifra el mensaje y lo envía en base64
            mensajeCifrado = cifrar(mensaje, client);

            // Codifica, convierte byte[] a una string codificada en base64
            String mensajeCodificado = Base64.getEncoder().encodeToString(mensajeCifrado);
                        
            // Envía la pregunta:
            out.println(mensajeCodificado);
            out.flush();

            // Recibe la respuesta:
            String respuesta = in.readLine();
            
            // Interpretamos los campos del mensaje:
            String[] campos = respuesta.split(" ");

            // Si es un error, lo comentamos:
            if (campos[0].compareTo("Error") == 0) {
                System.out.println("Error! Has enviado un mensaje incorrecto.");
            } else {
                System.out.println("Mensaje correcto.");
                System.out.println(respuesta.substring(26)); 
            }

            in.close();
            out.close();

        } catch (IOException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ClienteTCP.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /**
     * Método auxiliar para mostrar mensajes por pantalla
     *
     * @param mensaje
     * @param simple
     *
     */
    private static void mostrar(String mensaje, boolean simple) {
        System.out.print(((simple) ? "" : "Cliente: ") + mensaje + ((simple) ? "\n" : ""));
    }

    /**
     * Cifra texto plano con el algoritmo simétrico DES dada una clave
     * 
     * @param mensaje Texto plano a cifrar
     * @param person Objeto de la clase DiffieHellamn que contienen la clave secreta
     * 
     * @return Texto cifrado
     * 
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    private static byte[] cifrar(String mensaje, DiffieHellman person) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] textoCifrado;

        SecretKeySpec keySpec = new SecretKeySpec(person.getSecretKey(), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        textoCifrado = cipher.doFinal(mensaje.getBytes());

        return textoCifrado;
    }
}
