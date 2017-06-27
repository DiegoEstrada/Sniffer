/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

/**
 *
 * @author Diego EG
 */

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import javax.swing.JFrame;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;


public class Estadisticas {
    
    Map<String,Integer> datospaquetes;
    JFreeChart grafica;
    DefaultCategoryDataset datos = new DefaultCategoryDataset();
    
    public Estadisticas()
    {
        datospaquetes = new HashMap();
        
    }
    
    public void iniciarDatosenCero()
    {
         datospaquetes.put("Ethernet", 0);
         datospaquetes.put("IEEE 802.03", 0);
         datospaquetes.put("IP versión 4", 0);
         datospaquetes.put("ARP", 0);
         datospaquetes.put("UDP", 0);
         datospaquetes.put("TCP",0);
         datospaquetes.put("ICMP",0);
    }
    public void incrementarValor(String llave)
    {
        int valor;
        String nombre;
        Iterator it = datospaquetes.keySet().iterator();
        
        while(it.hasNext())
        {
            nombre = it.next().toString(); //Aqui esta contenida la llave del map
            if(nombre.contains(llave))
            {
                valor = datospaquetes.get(nombre);
                valor++;
                datospaquetes.replace(nombre, valor);
                System.out.println("Se incrementa "+nombre+ " a "+valor);
                break;
            }
            
        }
    }
    public void generarEstadistica()
    {
        int valor;
        String llave;
        Iterator it = datospaquetes.keySet().iterator();
        
        while(it.hasNext())
        {
            llave = it.next().toString(); //Aqui esta contenida la llave del map
            
                valor = datospaquetes.get(llave);
                datos.addValue(valor, llave, "Paquetes");
        }
        
        grafica = ChartFactory.createBarChart("Paquetes analizados","", "", datos,
        PlotOrientation.VERTICAL, true, false, false);
        ChartPanel panel = new ChartPanel(grafica);

        JFrame Ventana = new JFrame("Estadisticas de los paquetes recibidos");
        Ventana.getContentPane().add(panel);
        Ventana.pack();
        Ventana.setVisible(true);
        Ventana.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    }
}
