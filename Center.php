<?php
$baseband_ticket=GETWILDCARDTICKETGSM($BasebandMasterKeyHash, $BasebandChipID, $BasebandSerialNumber, $BuildVersion, $productType, $productVersion, $RegulatoryModelNumber,$activationRandomness, $serialNumber);


file_put_contents('ActivationFiles/'.$serialNumber.'/Wildcard.der', $baseband_ticket);
?>
