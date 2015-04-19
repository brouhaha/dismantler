def hex8_intel(val):
    """Return hex constant for byte in Intel assembler format."""
    valstr = '{:02X}h'.format(val)
    if valstr[0] in ['A', 'B', 'C', 'D', 'E', 'F']:
        valstr = '0'+valstr
    return valstr

def hex16_intel(val):
    """Return hex constant for word in Intel assembler format."""
    valstr = '{:04X}h'.format(val)
    if valstr[0] in ['A', 'B', 'C', 'D', 'E', 'F']:
        valstr = '0'+valstr
    return valstr

def signed_byte(val):
    """Interpret data as signed 8-bit value, return integer."""
    val = val & 0xFF
    if val > 0x7F:
        val = ((val ^ 0xFF) + 1) * -1
    return val
            
    
