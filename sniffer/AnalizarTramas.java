/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author Diego EG
 */
public class AnalizarTramas extends javax.swing.JFrame {

    private File archivo;
    private File archivoAGuardar;
    private int segundos;
    private int npaquetes;
    private int modo;
    private int tampaquetes;
    private int npaquetesrecibidos;
    private String filtros[];
    private String res;
    private Estadisticas estadisticas;
    
    public AnalizarTramas(File archivo, int segundos, int npaquetes, int modo, int tampaquetes, String filtros[])
    {
        this.archivo = archivo;
        this.segundos = segundos;
        this.npaquetes = npaquetes;
        this.tampaquetes = tampaquetes;
        this.npaquetesrecibidos = 0;
        this.filtros = filtros;
        this.res = "";
        initComponents();
        this.jcbInterfaces.removeAllItems();
        DefaultListModel listaComboBox = new DefaultListModel();
        DefaultListModel listaJList = new DefaultListModel();
        listaJList.addElement("Ningun paquete recibido");
        /*
        System.out.println("archivo -> " + this.archivo);
        System.out.println("segundos -> "+ this.segundos);
        System.out.println("tam paquetes -> "+ this.tampaquetes);
        System.out.println("num paquetes -> "+ this.npaquetes);
        System.out.println("modo -> "+this.modo);
        System.out.println("filtros -> "+this.filtros.length);
        */
        estadisticas = new Estadisticas();
        estadisticas.iniciarDatosenCero();
        mostrarDispositivos();
    }
     private static String asString(final byte[] mac) {
    final StringBuilder buf = new StringBuilder();
    for (byte b : mac) {
      if (buf.length() != 0) {
        buf.append(':');
      }
      if (b >= 0 && b < 16) {
        buf.append('0');
      }
      buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
    }

        return buf.toString();
    }


    

    
     public PcapIf obtenerDireccionMacInterfazRed()
    {
        int i = this.jcbInterfaces.getSelectedIndex();
        List <PcapIf> dispositivos = obtenerListaDispositivos();
        PcapIf device = dispositivos.get(i);
        
        return device;
    }
    
    public void mostrarDispositivos()
    {
        int i = 0;
        String informacion;
        byte[] MACo;
        List <PcapIf> dispositivos = obtenerListaDispositivos();
        
        this.jcbInterfaces.removeAllItems();
       
                try{
		for (PcapIf device : dispositivos) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        i++;
                        informacion = "# "+i+" : "+device.getName()+ " [ "+description+" ] " +dir_mac;
                        this.jcbInterfaces.addItem(informacion);
                        
                        //System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);

		}//for
                } catch (IOException ex) {
                    System.out.println("Excepcion atrapada -> "+ ex.getMessage());
        }
    }
            
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jlbInstrucciones = new javax.swing.JLabel();
        jcbInterfaces = new javax.swing.JComboBox<>();
        jlbPaquetesRecibidos = new javax.swing.JLabel();
        jbEstadisticas = new javax.swing.JButton();
        jbRegresar = new javax.swing.JButton();
        jbIniciar = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        TextArea = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Analizar tramas");

        jlbInstrucciones.setFont(new java.awt.Font("SansSerif", 1, 12)); // NOI18N
        jlbInstrucciones.setText("Selecciona la interfaz a utilizar");

        jcbInterfaces.setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N
        jcbInterfaces.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));

        jlbPaquetesRecibidos.setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N
        jlbPaquetesRecibidos.setText("Paquetes recibidos.");

        jbEstadisticas.setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N
        jbEstadisticas.setText("Estadisticas");
        jbEstadisticas.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbEstadisticasActionPerformed(evt);
            }
        });

        jbRegresar.setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N
        jbRegresar.setText("Regresar");
        jbRegresar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbRegresarActionPerformed(evt);
            }
        });

        jbIniciar.setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N
        jbIniciar.setText("Iniciar");
        jbIniciar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbIniciarActionPerformed(evt);
            }
        });

        TextArea.setColumns(20);
        TextArea.setRows(5);
        jScrollPane2.setViewportView(TextArea);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jlbInstrucciones)
                        .addGap(55, 55, 55)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jbIniciar)
                            .addComponent(jcbInterfaces, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                            .addGap(338, 338, 338)
                            .addComponent(jbEstadisticas)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jbRegresar))
                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                            .addGap(21, 21, 21)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 756, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(jlbPaquetesRecibidos)))))
                .addContainerGap(25, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jlbInstrucciones)
                    .addComponent(jcbInterfaces, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(20, 20, 20)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jlbPaquetesRecibidos)
                    .addComponent(jbIniciar))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 297, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jbEstadisticas))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(20, 20, 20)
                        .addComponent(jbRegresar)))
                .addGap(42, 42, 42))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jbEstadisticasActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbEstadisticasActionPerformed
        this.estadisticas.generarEstadistica();
    }//GEN-LAST:event_jbEstadisticasActionPerformed

    private void jbIniciarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbIniciarActionPerformed
        PcapIf device = obtenerDireccionMacInterfazRed();
        generarTramas(device);
        System.out.println(this.filtros[0]);
        System.out.println(this.filtros[1]);
        System.out.println(this.modo);
        System.out.println(this.segundos);
        
    }//GEN-LAST:event_jbIniciarActionPerformed

    private void jbRegresarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbRegresarActionPerformed
        Inicio formularioInico = new Inicio();
        formularioInico.setVisible(true);
        this.setVisible(false);
    }//GEN-LAST:event_jbRegresarActionPerformed
 
    public List<PcapIf> obtenerListaDispositivos()
    {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
                
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			
		}
                
                return alldevs;

    }
    
    public void generarTramas(PcapIf device)
    {
        Pcap pcap =null;
        mostrarIPMACS(device);
                int snaplen = this.tampaquetes;           // Capture all packets, no trucation
		int flags = asigmarModo(); // capture all packets
		int timeout = this.segundos * 1000;           // X seconds in millis
                StringBuilder errbuf = new StringBuilder();
                
                if (this.archivo!=null )
                {
                    pcap = Pcap.openOffline(archivo.getAbsolutePath(), errbuf);
                        if (pcap == null) {
                            System.err.printf("Error while opening device for capture: "+ errbuf.toString());
                            System.out.println("Se realizara captura al vuelo");
                        }    
                }
                 else
                {
                   pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
                }
               
		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}//if

                       /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression =asignarFiltros(); // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
                /****************/


		/***************************************************************************
		 * Third we create a packet handler which will receive packets from the
		 * libpcap loop.
		 **********************************************************************/
                
                    PcapDumper dumper = pcap.dumpOpen("traza.cap"); // output file
                    
                    PcapHandler<PcapDumper> dumpHandler = new PcapHandler<PcapDumper>() {
                        
			public void nextPacket(PcapDumper dumper, long seconds, int useconds,
			    int caplen, int len, ByteBuffer buffer) {
                                System.out.println("Guardando traza");
				dumper.dump(seconds, useconds, caplen, len, buffer);
			}
                        
		};
                    
                
                
		
                PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			public void nextPacket(PcapPacket packet, String user) {
                            
                            
                            //d.dump(packet, errbuf);
                            String paqueterecibido ="\nPaquete recibido el  "+new Date(packet.getCaptureHeader().timestampInMillis())
                                        +" bytes capturados = "+packet.getCaptureHeader().caplen()
                                        +" tamaño original "+packet.getCaptureHeader().wirelen()+" "+user;
                            res = res + paqueterecibido+"\n";
                               
                                
				System.out.printf("Paquete recibido el %s bytes capturados=%-4d tam original=%-4d %s\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                                
                                res = res + "Dirección MAC destino: "; 
                                System.out.println("MAC destino:");
                                for(int i=0;i<6;i++){
                                    res = res+" "+Integer.toHexString(packet.getUByte(i)).toUpperCase();
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                               
                                System.out.println("");
                                
                                res = res + "\nDirección MAC origen: ";
                                System.out.println("MAC origen:");
                                for(int i=6;i<12;i++){
                                res = res+" "+Integer.toHexString(packet.getUByte(i)).toUpperCase();
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                              
                                System.out.println("");
                                res = res + "\nTipo: ";
                                System.out.println("Tipo:");
                                for(int i=12;i<14;i++){
                                    res = res + " "+Integer.toHexString(packet.getUByte(i)).toUpperCase();
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                
                                int tipo = (packet.getUByte(12)*256)+packet.getUByte(13);
                                System.out.printf("\nTipo= %d",tipo);
                                res = res + " = "+tipo+"\n";
                              
                            
                          
                           
                                
                           IEEE802dot3 i3e = new IEEE802dot3();
                            if (packet.hasHeader(i3e)) {
                                System.out.println("\nTrama IEEE 802.3");
                               res = res + "-->Trama IEEE 802.3.\n";
                               
                               estadisticas.incrementarValor("IEEE 802.03");
                            }
                            
                              Ethernet ethernet = new Ethernet();
                           if (packet.hasHeader(ethernet))
                           {
                               System.out.println("\nTrama ETHERNET");
                               res = res + "-->Trama ETHERNET.\n";
                               System.out.println("ALGO 1 "+ethernet.typeDescription());
                               System.out.println("ALGO 2 "+ethernet.type());
                               //System.out.println("Checksum "+ethernet.checksum() );
                               res = res + ethernet.getDescription()+"\n";
                               res = res +" tipo " +ethernet.type()+"\n";
                               //res = res + " checksum "+ ethernet.checksum();
                               estadisticas.incrementarValor("Ethernet");
                           }
                           
                            
                            Arp arp = new Arp();
                             if (packet.hasHeader(arp)) {
                                System.out.println("\nARP");
                                res = res + "-->Trama ARP.\n";
                                    System.out.println("Tipo de hardware "+ arp.hardwareType() + " = " +arp.hardwareTypeDescription());
                                res = res + "Tipo de hardware "+arp.hardwareType() + " = "+ arp.hardwareTypeDescription()+"\n";
                                    System.out.println("Tamano de hardware "+arp.hlen());
                                res = res + "Tamaño de hardware "+ arp.hlen()+"\n";
                                    System.out.println("Tipo de protocolo " +arp.protocolTypeDescription());
                                res = res + "Tipo de protocolo "+arp.protocolTypeDescription()+"\n";
                                    System.out.println("Tamano de protocolo "+arp.plen());
                                res = res +"Tamaño de prototocolo "+arp.plen()+"\n";
                                    System.out.println("Operacion "+arp.operation()+" = "+arp.operationDescription());
                                res =res + "Operación "+arp.operation()+ " = "+ arp.operationDescription()+"\n";
                                    System.out.println("MAC origen "+FormatUtils.mac(arp.sha()));
                                res = res +"Dirección MAC origen "+FormatUtils.mac(arp.sha())+"\n";
                                    System.out.println("IP origen " +FormatUtils.ip(arp.spa()));
                                res = res +"Dirección IP origen "+FormatUtils.ip(arp.spa())+"\n";
                                    System.out.println("MAC destino "+FormatUtils.mac(arp.tha()));
                                res = res +"Dirección MAC destino "+FormatUtils.mac(arp.tha())+"\n";
                                    System.out.println("IP destino " +FormatUtils.ip(arp.tpa()));
                                res = res +"Dirección IP destino "+FormatUtils.ip(arp.tpa())+"\n";
                                
                                estadisticas.incrementarValor("ARP");
                            }
                             
                            Ip4 ip4 = new Ip4();
                            if (packet.hasHeader(ip4)) {
                                System.out.println("\nIP version 4");
                               res = res + "-->Trama IP Versión 4.\n";
                                    System.out.println("Version "+ip4.version());
                               res = res + "Versión "+ip4.version()+"\n";
                                    System.out.println("Longitud de cabecera "+ip4.hlen());
                               res = res + "Longitud de cabecera "+ip4.hlen()+"\n";
                                    System.out.println("Tipo de servicio "+ip4.tos());
                               res = res + "Tipo de servico "+ip4.tos()+"\n";
                                    System.out.println("Longitud total "+ip4.length());
                               res = res + "Longitud total "+ip4.length()+"\n";
                                    System.out.println("Identifcador "+ip4.id());
                               res = res + "Identificador "+ip4.id()+"\n";
                                    System.out.println("Banderas "+ip4.flags_DF());
                               res = res + "Bnaderas "+ip4.flags_DF()+"\n";
                                    System.out.println("Offset "+ip4.offset() +" = "+ip4.offsetDescription());
                               res = res + "Offset "+ip4.offset()+"\n";
                                    System.out.println("TTL "+ ip4.ttl());
                               res = res + "TTL "+ip4.ttl()+"\n";
                                //System.out.println("Protocolo ");
                                    System.out.println("Checksum "+ip4.checksum());
                               res = res + "Checksum "+ip4.checksum()+"\n";
                                    System.out.println("Dirección IP origen "+FormatUtils.ip(ip4.source()));
                               res = res + "Dirección IP origen "+FormatUtils.ip(ip4.source())+"\n";
                                    System.out.println("Direccion IP destino "+FormatUtils.ip(ip4.destination()));
                               res = res + "Dirección IP origen "+FormatUtils.ip(ip4.destination())+"\n";
                                    //System.out.println("Opciones ");
                                    //System.out.println("Relleno ");
                                
                               estadisticas.incrementarValor("IP versión 4");
                            }
                                    
                            
                            Udp udp = new Udp();
                            if (packet.hasHeader(udp)) {
                                
                                System.out.println("\nUDP 4");
                               res = res + "-->Trama UDP.\n";

                                res = res + "Puerto origen:" + udp.source() + "\nPuerto destino:" + udp.destination() + "\n";
                                    System.out.println("Puerto origen:" + udp.source() + "\nPuerto destino:" + udp.destination());
                                res = res + "Longitud de mensaje: " + udp.length() + "\n";
                                    System.out.println("Longitud de mensjae: " + udp.length());
                                res = res + "Checksum: " + udp.checksum();
                                    System.out.printf("Checksum: " + "%02X", udp.checksum());
                                //res = res + "---" + udp.isChecksumValid() + "\n";
                                //System.out.printf("---" + udp.isChecksumValid() + "\n");  
                                
                                estadisticas.incrementarValor("UDP");
                                }
                            
                            
                            Tcp tcp = new Tcp();

                            if (packet.hasHeader(tcp)) {

                                    System.out.println("\nTCP ");
                                res = res + "-->Trama TCP.\n";
                                res = res + "Puerto origen:" + tcp.source() + "\n";
                                    System.out.println("Puerto origen:" + tcp.source());
                                res = res + "Puerto destino:" + tcp.destination() + "\n";
                                    System.out.println("Puerto destino:" + tcp.destination());
                                res = res + "Número de secuencia: " + tcp.seq() + "\nNúmero de acuse " + tcp.ack()+"\n";
                                    System.out.println("Numero de secuencia " + tcp.seq() + "\nNumero de acuse " + tcp.ack()+"\n");
                                res = res +"Longitud de cabecera "+tcp.hlen()+"\n";
                                    System.out.println("Longitud de cabecera "+tcp.hlen());
                                res = res + "Reservado "+tcp.reserved()+"\n";
                                    System.out.println("Reservado "+tcp.reserved());
                                res = res + "Banderas "+ tcp.flagsCompactString()+"\n";
                                    System.out.println("Banderas "+ tcp.flagsCompactString());
                                res = res + "Ventana: " + tcp.window() + "\n";
                                    System.out.println("Ventana: " + tcp.window());
                                res = res + "Checksum: " + (+tcp.checksum()+"\n");
                                    System.out.printf("Checksum: " + "%02X", tcp.checksum());
                                res = res + "Puntero urgente "+tcp.urgent()+"\n";
                                    System.out.println("Puntero urgente "+tcp.urgent());
                                res = res + "\nBandera de acuse: " + tcp.flags_ACK() + "\nBandera sincronización: " + tcp.flags_SYN();
                                    System.out.println("Bandera de acuse: " + tcp.flags_ACK() + "\nBandera de sincronizacion: " + tcp.flags_SYN());
                                    
                                    
                                    
                                 estadisticas.incrementarValor("TCP");   
                               }
                            
                            
                            Icmp icmp = new Icmp();
                            if (packet.hasHeader(icmp)) {
                                    System.out.println("ICMP\n");
                                res = res +"-->Trama ICMP.\n";
                                    System.out.println("Tipo:" + icmp.type());
                                res = res + "Tipo " + icmp.type()+ " = "+ icmp.getDescription()+"\n";
                                System.out.println("TIPO "+icmp.typeEnum());
                                    System.out.println("Codigo "+icmp.code());
                                res = res + "Código "+icmp.code()+"\n";
                                    System.out.printf("Checksum: " + "%02X", icmp.checksum());
                                res = res + "Checksum: " + icmp.checksum()+"\n";
                               
                                estadisticas.incrementarValor("ICMP");
                            }
                            
                           
                            
                            System.out.println("Trama capturada:");
                            res = res + "\nTrama capturada\n";
                            for(int l=0;l<packet.size();l++){
                                    res += " "+Integer.toHexString(packet.getUByte(l)).toUpperCase();
                                System.out.printf("%02X ",packet.getUByte(l));
                                    if(l%16==15){
                                        System.out.println("");
                                        System.out.println("");
                                        res += "\n";
                                    }
                            }
                            res = res +"\n";
                            
                        }
                       
           
		};
                
                
                  


		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets. The loop
		 * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
		 * is needed by JScanner. The scanner scans the packet buffer and decodes
		 * the headers. The mapping is done automatically, although a variation on
		 * the loop method exists that allows the programmer to sepecify exactly
		 * which protocol ID to use as the data link type for this pcap interface.
		 **************************************************************************/
		pcap.loop(this.npaquetes, jpacketHandler, "Sniffer");
                TextArea.setText(res);
                    
                pcap.close();
                
                res = "";
                
                
    }
    public void agregarTextojtArea(String cadena)
    {
        this.TextArea.setText(cadena);
    }
    

    
    public void mostrarIPMACS(PcapIf device)
    {
            try {
            
            Iterator<PcapAddr> it1 = device.getAddresses().iterator();
            while(it1.hasNext()){
                PcapAddr dir = it1.next();//dir, familia, mascara,bc
                PcapSockAddr direccion1 =dir.getAddr();
                byte[]d_ip = direccion1.getData(); //esta sera la ip origen
                int familia=direccion1.getFamily();
                int[]ipv4_1 = new int[4];
                if(familia==org.jnetpcap.PcapSockAddr.AF_INET){
                    ipv4_1[0]=((int)d_ip[0]<0)?((int)d_ip[0])+256:(int)d_ip[0];
                    ipv4_1[1]=((int)d_ip[1]<0)?((int)d_ip[1])+256:(int)d_ip[1];
                    ipv4_1[2]=((int)d_ip[2]<0)?((int)d_ip[2])+256:(int)d_ip[2];
                    ipv4_1[3]=((int)d_ip[3]<0)?((int)d_ip[3])+256:(int)d_ip[3];
                    String ip_interfaz = ipv4_1[0]+"."+ipv4_1[1]+"."+ipv4_1[2]+"."+ipv4_1[3];
                    System.out.println("\nInterfaz que se usara:"+ip_interfaz);
                    
                    
                    
                    
                }
            }
        }catch(Exception e){System.out.println("Exception identificando ip-> "+e.getMessage());}
    }
    
    public int asigmarModo(){
        int modo=0;
        switch(this.modo)
                {
            case 0:
                modo = Pcap.MODE_PROMISCUOUS;
                break;
            case 1:
                modo = Pcap.MODE_NON_PROMISCUOUS;
                break;
            case 2: 
                modo = Pcap.MODE_BLOCKING;
                break;
            case 3:
                modo = Pcap.MODE_NON_BLOCKING;
                break;
            default: 
                System.out.println("Se recibe un numero mayor que 3 ");
                modo = 0;
                break;
                }
        return modo;
    }
    
    public String asignarFiltros()
    {
        String expresion = "";
        
        
        
            if (this.filtros.length==1)
            {
                if(this.filtros[0].contains("ieee"))
                {
                    expresion = "ieee802.3";
                }
                else
                {
                    expresion = "ethernet";
                }
            }
            else{
                //Se asume que el filtro es compuesto por ethernet y algun otro
                if(filtros[1]!=null){
                    switch(this.filtros[1])
                    {
                        case "arp":
                            expresion = "arp";
                            break;
                        case "ip":
                            expresion = "ipv4";
                            break;
                        case "tcp":
                            expresion = "tcp";
                            break;
                        case "udp":
                            expresion = "udp";
                            break;
                        case "igmp":
                            expresion = "igmp";
                            break;
                        case "icmp":
                            expresion = "icmp";
                            break;
                        default :
                            System.out.println("Filtro invalido");
                            break;
                    
                    }
                }    
            }    
        
        return expresion;
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea TextArea;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JButton jbEstadisticas;
    private javax.swing.JButton jbIniciar;
    private javax.swing.JButton jbRegresar;
    private javax.swing.JComboBox<String> jcbInterfaces;
    private javax.swing.JLabel jlbInstrucciones;
    private javax.swing.JLabel jlbPaquetesRecibidos;
    // End of variables declaration//GEN-END:variables
}
