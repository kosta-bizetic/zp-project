package bk160121ddl160135d;

import java.util.List;

import javax.swing.table.AbstractTableModel;

@SuppressWarnings("serial")
public class KeysTableModel extends AbstractTableModel {
    private List<List<String>> data;
    private String[] columns = {
            "Name", "Email", "Key-ID"
    };

    public KeysTableModel(List<List<String>> data) {
        this.data = data;
    }

    @Override
    public int getRowCount() {
        return data.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public String getColumnName(int col) {
        return columns[col];
    }

    @Override
    public Object getValueAt(int row, int column) {
        return data.get(row).get(column);
    }
}
