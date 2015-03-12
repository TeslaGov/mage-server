/**
 * angular-strap
 * @version v2.2.1 - 2015-03-10
 * @link http://mgcrea.github.io/angular-strap
 * @author Olivier Louvignes (olivier@mg-crea.com)
 * @license MIT License, http://www.opensource.org/licenses/MIT
 */
'use strict';

angular.module('mgcrea.ngStrap.select').run(['$templateCache', function($templateCache) {

  $templateCache.put('select/select.tpl.html', '<ul tabindex="-1" cl***REMOVED***="select dropdown-menu" ng-show="$isVisible()" role="select"><li ng-if="$showAllNoneButtons"><div cl***REMOVED***="btn-group" style="margin-bottom: 5px; margin-left: 5px"><button type="button" cl***REMOVED***="btn btn-default btn-xs" ng-click="$selectAll()">{{$allText}}</button> <button type="button" cl***REMOVED***="btn btn-default btn-xs" ng-click="$selectNone()">{{$noneText}}</button></div></li><li role="presentation" ng-repeat="match in $matches" ng-cl***REMOVED***="{active: $isActive($index)}"><a style="cursor: default" role="menuitem" tabindex="-1" ng-click="$select($index, $event)"><i cl***REMOVED***="{{$iconCheckmark}} pull-right" ng-if="$isMultiple && $isActive($index)"></i> <span ng-bind="match.label"></span></a></li></ul>');

}]);