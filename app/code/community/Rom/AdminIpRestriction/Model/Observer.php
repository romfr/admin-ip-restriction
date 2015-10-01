<?php
/**
 * @category    Rom
 * @package     Rom_AdminIpRestriction
 * @copyright   Copyright (c) 2015 ROM - Agence de communication (http://www.rom.fr/)
 * @license     http://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 * @author      André Herrn <info@andre-herrn.de>
 */
class Rom_AdminIpRestriction_Model_Observer
{
    /**
     * Check if admin is allowed to login
     * 
     * @param Varien_Event_Observer $observer
     * @return void
     */
    public function checkLogin($observer)
    {
        //Backend users with "Adminstrators" role can login anyway
        if ('Administrators' == $this->getAdminRole()) {
            return;
        }
        foreach ($this->getAllowedIps() as $allowedIp) {
            if (false !== strpos($_SERVER['REMOTE_ADDR'], $allowedIp)) {
                //IP or IP part was found, return and continue admin login
                return;
            }
        }
        //IP not found, deny admin login
        $adminSession = Mage::getSingleton('admin/session');
        $adminSession->unsetAll();
        $adminSession->getCookie()->delete($adminSession->getSessionName());
        Mage::throwException(Mage::helper('adminhtml')->__('Invalid IP.'));
    }

    /**
     * Get allowed IPs for backend login
     * 
     * @return array
     */
    protected function getAllowedIps()
    {
        $ipTextField = Mage::getStoreConfig('admin/security/allowed_ips');
        $ipTextField = explode("\n",$ipTextField);

        $allowedIps = array();
        foreach ($ipTextField as $ipLine) {
            $ipString = explode(" ", $ipLine);
            if (!empty($ipString[0])) $allowedIps[] = $ipString[0];
        }
        return $allowedIps;
    }

    /**
     * Get admin role of backend user
     * 
     * @return array
     */
    protected function getAdminRole()
    {
        $adminSession = Mage::getSingleton('admin/session');
        if ($adminSession->isLoggedIn()) {
            return $adminSession->getUser()->getRole()->getRoleName();
        } else {
            return "unknown";
        }
    }
}