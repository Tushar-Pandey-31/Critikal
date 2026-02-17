
pragma solidity ^0.8.0;

contract Parent {
    uint public parentVal;

    function setParentVar(uint _val) public {
        parentVal = _val;
    }
}

contract Complex is Parent {
    uint public value;

    function setValue(uint _value) public {
        value = _value;
        internalUpdate(_value);
    }

    function internalUpdate(uint _value) internal {
        value = _value + 1;
    }

    function getValue() public view returns (uint) {
        return value;
    }

    function callParent(uint _val) public {
        setParentVar(_val);
    }
}
