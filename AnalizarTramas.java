/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 *
 * @author Diego EG
 */
public class AnalizarTramas extends javax.swing.JFrame {

    /**
     * Creates new form AnalizarTramas
     */
    
    public AnalizarTramas(File archivo, int segundos, int npaquetes, int modo, int tampaquetes)
    {
        initComponents();
        this.jcbInterfaz.removeAllItems();
        DefaultListModel listaComboBox = new DefaultListModel();
        DefaultListModel listaJList = new DefaultListModel();
        listaJList.addElement("Ningun paquete recibido");
        this.jlPaquetes.setModel(listaJList);
        mostrarDispositivos();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jlbInstrucciones = new javax.swing.JLabel();
        jcbInterfaz = new javax.swing.JComboBox<>();
        jScrollPane1 = new javax.swing.JScrollPane();
        jlPaquetes = new javax.swing.JList<>();
        jlbPaquetesRecibidos = new javax.swing.JLabel();
        jbDetener = new javax.swing.JButton();
        jbEstadisticas = new javax.swing.JButton();
        jbGuardarTraza = new javax.swing.JButton();
        jbRegresar = new javax.swing.JButton();
        jbIniciar = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jlbInstrucciones.setText("Selecciona la interfaz a utilizar");

        jcbInterfaz.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));

        jlPaquetes.setModel(new javax.swing.AbstractListModel<String>() {
            String[] strings = { "Item 1", "Item 2", "Item 3", "Item 4", "Item 5" };
            public int getSize() { return strings.length; }
            public String getElementAt(int i) { return strings[i]; }
        });
        jScrollPane1.setViewportView(jlPaquetes);

        jlbPaquetesRecibidos.setText("Paquetes recibidos.");

        jbDetener.setText("Detener");
        jbDetener.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbDetenerActionPerformed(evt);
            }
        });

        jbEstadisticas.setText("Estadisticas");
        jbEstadisticas.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbEstadisticasActionPerformed(evt);
            }
        });

        jbGuardarTraza.setText("Guardar");
        jbGuardarTraza.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbGuardarTrazaActionPerformed(evt);
            }
        });

        jbRegresar.setText("Regresar");
        jbRegresar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbRegresarActionPerformed(evt);
            }
        });

        jbIniciar.setText("Iniciar");
        jbIniciar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jbIniciarActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jbRegresar))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(jlbInstrucciones)
                                .addGap(55, 55, 55)
                                .addComponent(jcbInterfaz, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jbIniciar))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(21, 21, 21)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jbDetener)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(jbEstadisticas)
                                        .addGap(95, 95, 95)
                                        .addComponent(jbGuardarTraza))
                                    .addComponent(jlbPaquetesRecibidos, javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 466, javax.swing.GroupLayout.PREFERRED_SIZE))))
                        .addGap(0, 48, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jlbInstrucciones)
                    .addComponent(jcbInterfaz, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jbIniciar))
                .addGap(22, 22, 22)
                .addComponent(jlbPaquetesRecibidos)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 302, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 18, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jbEstadisticas)
                    .addComponent(jbDetener)
                    .addComponent(jbGuardarTraza))
                .addGap(18, 18, 18)
                .addComponent(jbRegresar)
                .addGap(8, 8, 8))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jbEstadisticasActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbEstadisticasActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jbEstadisticasActionPerformed

    private void jbGuardarTrazaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbGuardarTrazaActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jbGuardarTrazaActionPerformed

    private void jbIniciarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbIniciarActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jbIniciarActionPerformed

    private void jbRegresarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbRegresarActionPerformed
        Inicio formularioInico = new Inicio();
        formularioInico.setVisible(true);
        this.setVisible(false);
    }//GEN-LAST:event_jbRegresarActionPerformed

    private void jbDetenerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jbDetenerActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jbDetenerActionPerformed

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
    
    public void mostrarDispositivos()
    {
        int i = 0;
        String informacion;
        List <PcapIf> dispositivos = obtenerListaDispositivos();
        
        this.jcbInterfaz.removeAllItems();
       
                try{
		for (PcapIf device : dispositivos) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        i++;
                        informacion = "# "+i+" : "+device.getName()+ " [ "+description+" ] " +dir_mac;
                        this.jcbInterfaz.addItem(informacion);
                        //System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);

		}//for
                } catch (IOException ex) {
                    System.out.println("Excepcion atrapada -> "+ ex.getMessage());
        }
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton jbDetener;
    private javax.swing.JButton jbEstadisticas;
    private javax.swing.JButton jbGuardarTraza;
    private javax.swing.JButton jbIniciar;
    private javax.swing.JButton jbRegresar;
    private javax.swing.JComboBox<String> jcbInterfaz;
    private javax.swing.JList<String> jlPaquetes;
    private javax.swing.JLabel jlbInstrucciones;
    private javax.swing.JLabel jlbPaquetesRecibidos;
    // End of variables declaration//GEN-END:variables
}